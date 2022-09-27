use async_trait::async_trait;
use axum::{
    extract::{FromRequest, RequestParts},
    http::StatusCode,
    Json, TypedHeader,
};
use delicious_jose::{
    jwa::SignatureAlgorithm,
    jws::{Decoded, Secret},
};
use headers_core::{Header, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::postgres::Client;

#[derive(Deserialize)]
pub struct SessionBody {
    website: Uuid,
    hostname: String,
    screen: String,
    language: String,
}

pub async fn post(body: Json<SessionBody>) {}

#[derive(Deserialize, Serialize)]
pub struct Session {
    website_id: i32,
    session_id: i32,
}

#[async_trait]
impl<B: Send> FromRequest<B> for Session {
    type Rejection = StatusCode;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let db: &Client = req
            .extensions()
            .get()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

        let cache: Option<TypedHeader<UmamiCache>> = req.extract().await.unwrap_or(None);
        if let Some(TypedHeader(cache)) = cache {
            let secret: &Secret = req
                .extensions()
                .get()
                .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

            if let Ok(session) =
                Decoded::<Session, ()>::decode_json(&cache.0, secret, SignatureAlgorithm::HS256)
            {
                return Ok(session.payload);
            }
        }
        todo!()
    }
}

pub struct UmamiCache(delicious_jose::Compact);

impl Header for UmamiCache {
    fn name() -> &'static HeaderName {
        static NAME: HeaderName = HeaderName::from_static("x-umami-cache");
        &NAME
    }

    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(
        values: &mut I,
    ) -> Result<Self, headers_core::Error> {
        values
            .next()
            .and_then(|v| v.to_str().ok())
            .map(delicious_jose::Compact::decode)
            .map(UmamiCache)
            .ok_or_else(headers_core::Error::invalid)
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let value = self
            .0
            .as_str()
            .parse()
            .expect("Mime is always a valid HeaderValue");
        values.extend(::std::iter::once(value));
    }
}
