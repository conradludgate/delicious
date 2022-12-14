use async_trait::async_trait;
use axum::{
    extract::{FromRequest, RequestParts},
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
    response::{IntoResponse, Response},
    TypedHeader,
};
use no_way::{
    jwa::{cea, kma, sign},
    jwe::Encrypted, JWE,
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

        let token: Encrypted<kma::PBES2_HS256_A128KW> = token.token().parse()?;
        let jwe: JWE<_> = token.decrypt::<_, cea::A128CBC_HS256>(&secret.0)?;
        let jwt = jwe.payload.verify::<sign::HS256>(&secret.0)?;
        Ok(jwt.payload.private)
    }
}
