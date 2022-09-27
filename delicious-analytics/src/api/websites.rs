use crate::postgres::DbReconnector;
use axum::{extract::Query, http::StatusCode, BoxError, Extension, Json};
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
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
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<String>,
}

#[derive(Deserialize)]
pub struct Q {
    #[serde(default)]
    include_all: bool,
}

pub async fn get(
    _auth: Auth,
    query: Query<Q>,
    db: Extension<DbReconnector>,
) -> Result<Json<Vec<GetResponse>>, (StatusCode, String)> {
    match get_inner(query.include_all, db.0).await {
        Ok(r) => Ok(Json(r)),
        Err(e) => Err((StatusCode::BAD_REQUEST, format!("{e}"))),
    }
}

async fn get_inner(include_all: bool, db: DbReconnector) -> Result<Vec<GetResponse>, BoxError> {
    let rows = if include_all {
        db.client().await.get_all_websites().await?
    } else {
        // TODO: fix with auth
        db.client().await.get_user_websites(1).await?
    };

    Ok(rows
        .map_ok(|row| GetResponse {
            website_id: row.get(0),
            website_uuid: row.get(1),
            user_id: row.get(2),
            name: row.get(3),
            domain: row.get(4),
            share_id: row.get(5),
            created_at: row.get(6),
            account: row.try_get(7).ok(),
        })
        .try_collect()
        .await?)
}
