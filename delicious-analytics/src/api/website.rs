
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
        website_id: row.get(0),
        website_uuid: row.get(1),
        user_id: row.get(2),
        name: row.get(3),
        domain: row.get(4),
        share_id: row.get(5),
        created_at: row.get(6),
    })
}
