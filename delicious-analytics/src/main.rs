use std::env::{self, VarError};

use axum::{extract::RequestParts, routing::get, Extension, Router};
use postgres::DbReconnector;
use sha2::{Digest, Sha512};

mod postgres;

#[derive(Clone)]
pub struct SecretKey(Vec<u8>);

impl SecretKey {
    fn from_request<B>(req: &RequestParts<B>) -> &Self {
        req.extensions().get().unwrap()
    }
    fn to_jwk(&self) -> delicious_jose::jwk::JWK<()> {
        delicious_jose::jwk::JWK::new_octet_key(&self.0, ())
    }
    fn to_secret(&self) -> delicious_jose::jws::Secret {
        delicious_jose::jws::Secret::Bytes(self.0.clone())
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
    let mut key_hasher = Sha512::new();
    key_hasher.update(key);
    let key = SecretKey(hex::encode(key_hasher.finalize()).into_bytes());

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
