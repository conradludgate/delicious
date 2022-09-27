use async_trait::async_trait;
use axum::{
    extract::{FromRequest, RequestParts},
    headers::{authorization::Bearer, Authorization},
    http::StatusCode,
    TypedHeader,
};
use delicious_jose::{
    jwa::{kma, ContentEncryptionAlgorithm, SignatureAlgorithm},
    Compact, JWE, JWT,
};
use serde::{Deserialize, Serialize};

use crate::SecretKey;

#[derive(Debug, Serialize, Deserialize)]
pub struct Auth {
    is_admin: bool,
    user_id: i64,
    username: String,
}

#[async_trait]
impl<B: Send> FromRequest<B> for Auth {
    type Rejection = StatusCode;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let token: TypedHeader<Authorization<Bearer>> =
            req.extract().await.map_err(|_| StatusCode::UNAUTHORIZED)?;
        let secret = SecretKey::from_request(req);
        let jwk = secret.to_jwk();

        let token = Compact::decode(token.token());
        let token = token.try_into().map_err(|_| StatusCode::UNAUTHORIZED)?;
        let jwe = JWE::<()>::decrypt(
            token,
            &jwk,
            kma::PBES2::HS256_A128KW.into(),
            ContentEncryptionAlgorithm::A128CBC_HS256,
        )
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let jwt =
            JWT::<Auth, ()>::decode(&jwe.payload, &secret.to_secret(), SignatureAlgorithm::HS256)
                .map_err(|_| StatusCode::UNAUTHORIZED)?;
        Ok(jwt.payload.private)
    }
}
