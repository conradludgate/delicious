use std::env::{self, VarError};

use axum::{extract::RequestParts, routing::get, Extension, Router};
use postgres::DbReconnector;
use sha2::{Digest, Sha512};

mod postgres;

#[derive(Clone)]
pub struct SecretKey(delicious_jose::jwk::OctetKey);

impl SecretKey {
    fn from_request<B>(req: &RequestParts<B>) -> &Self {
        req.extensions().get().unwrap()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hash_salt = match env::var("HASH_SALT") {
        Ok(hash) => Some(hash),
        Err(VarError::NotPresent) => None,
        Err(e) => return Err(e.into()),
    };
    let database_url = env::var("DATABASE_URL")?;

    let key = hash_salt.as_deref().unwrap_or(&database_url);
    let key = SecretKey(delicious_jose::jwk::OctetKey::new(
        hex::encode(Sha512::new().chain_update(key).finalize()).into_bytes(),
    ));

    let db = DbReconnector::connect(database_url.parse()?).await?;

    let app = Router::new()
        .route("/api/website/:id", get(api::website::get))
        .route("/api/websites", get(api::websites::get))
        .layer(Extension(db))
        .layer(Extension(key));

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

mod api {
    pub mod auth;
    pub mod collect;
    pub mod website;
    pub mod websites;
}
