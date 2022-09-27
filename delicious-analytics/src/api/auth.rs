use async_trait::async_trait;
use axum::{
    extract::{FromRequest, RequestParts},
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
    response::{IntoResponse, Response},
    TypedHeader,
};
use delicious_jose::{
    jwa::{kma, ContentEncryptionAlgorithm, SignatureAlgorithm},
    jwe::Encrypted,
    JWT,
};
use serde::{Deserialize, Serialize};

use crate::SecretKey;

#[derive(Debug, Serialize, Deserialize)]
pub struct Auth {
    is_admin: bool,
    user_id: i64,
    username: String,
}

pub struct Unauthorized;

impl IntoResponse for Unauthorized {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, "401 Unauthorized").into_response()
    }
}

impl<E: std::error::Error> From<E> for Unauthorized {
    fn from(_: E) -> Self {
        Self
    }
}

#[async_trait]
impl<B: Send> FromRequest<B> for Auth {
    type Rejection = Unauthorized;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let token: TypedHeader<Authorization<Bearer>> = req.extract().await?;
        let secret = SecretKey::from_request(req);
        let jwk = secret.to_jwk();

        let token = Encrypted::<()>::decode(token.token())?;
        let jwe = token.decrypt(
            &jwk,
            kma::PBES2::HS256_A128KW.into(),
            ContentEncryptionAlgorithm::A128CBC_HS256,
        )?;
        let jwt = JWT::decode(&jwe.payload, &secret.to_secret(), SignatureAlgorithm::HS256)?;
        Ok(jwt.payload.private)
    }
}
