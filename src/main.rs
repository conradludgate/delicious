use std::env;

use axum::{routing::get, Extension, Router};
use postgres::DbReconnector;

mod postgres;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut db_conf = tokio_postgres::Config::new();
    db_conf
        .dbname(&env::var("DATABASE_NAME")?)
        .user(&env::var("DATABASE_USER")?)
        .password(&env::var("DATABASE_PASS")?)
        .host(&env::var("DATABASE_HOST")?)
        .port(env::var("DATABASE_PORT")?.parse()?);
    let db = DbReconnector::connect(db_conf).await?;

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/api/website/:id", get(api::website::get))
        .layer(Extension(db));

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

mod api {
    pub mod website {
        use crate::postgres::DbReconnector;
        use axum::{extract::Path, http::StatusCode, BoxError, Extension, Json};
        use serde::Serialize;
        use uuid::Uuid;

        #[derive(Serialize)]
        pub struct GetResponse {
            website_id: i32,
            website_uuid: Uuid,
            user_id: i32,
            name: String,
            domain: String,
            share_id: String,
            #[serde(with = "time::serde::rfc3339")]
            created_at: time::OffsetDateTime,
        }

        pub async fn get(
            id: Path<i32>,
            db: Extension<DbReconnector>,
        ) -> Result<Json<GetResponse>, (StatusCode, String)> {
            match get_inner(id.0, db.0).await {
                Ok(r) => Ok(Json(r)),
                Err(e) => Err((StatusCode::BAD_REQUEST, format!("{e}"))),
            }
        }

        async fn get_inner(id: i32, db: DbReconnector) -> Result<GetResponse, BoxError> {
            let row = db.client().await.get_website(id).await?;

            Ok(GetResponse {
                website_id: row.try_get("website_id")?,
                website_uuid: row.try_get("website_uuid")?,
                user_id: row.try_get("user_id")?,
                name: row.try_get("name")?,
                domain: row.try_get("domain")?,
                share_id: row.try_get("share_id")?,
                created_at: row.try_get("created_at")?,
            })
        }
    }
}
