use crate::postgres::DbReconnector;
use axum::{extract::Path, http::StatusCode, Extension, Json};
use serde::Serialize;
use uuid::Uuid;

use super::auth::Auth;

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
    _auth: Auth,
    id: Path<i32>,
    db: Extension<DbReconnector>,
) -> Result<Json<GetResponse>, (StatusCode, String)> {
    let row = db
        .client()
        .await
        .get_website(id.0)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match row {
        Some(row) => Ok(Json(GetResponse {
            website_id: row.get(0),
            website_uuid: row.get(1),
            user_id: row.get(2),
            name: row.get(3),
            domain: row.get(4),
            share_id: row.get(5),
            created_at: row.get(6),
        })),
        None => Err((StatusCode::NOT_FOUND, String::from("website not found"))),
    }
}
