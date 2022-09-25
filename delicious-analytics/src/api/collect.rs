use axum::Json;
use headers_core::{Header, HeaderName, HeaderValue};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct Session {
    website: Uuid,
    hostname: String,
    screen: String,
    language: String,
}



pub async fn post(body: Json<Session>) {

}

pub struct UmamiCache(delicious_jose::Compact);

impl Header for UmamiCache {
    fn name() -> &'static HeaderName {
        static NAME: HeaderName = HeaderName::from_static("x-umami-cache");
        &NAME
    }

    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, headers_core::Error> {
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
            .encode()
            .as_str()
            .parse()
            .expect("Mime is always a valid HeaderValue");
        values.extend(::std::iter::once(value));
    }
}
