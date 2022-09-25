use std::env;

use axum::{routing::get, Extension, Router};
use postgres::DbReconnector;

mod postgres;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut db_conf = tokio_postgres::Config::new();
    db_conf
        .dbname(&env::var("DATABASE_NAME")?)
        .user(&env::var("DATABASE_USER")?)
        .password(&env::var("DATABASE_PASS")?)
        .host(&env::var("DATABASE_HOST")?)
        .port(env::var("DATABASE_PORT")?.parse()?);
    let db = DbReconnector::connect(db_conf).await?;

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/api/website/:id", get(api::website::get))
        .route("/api/websites", get(api::websites::get))
        .layer(Extension(db));

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

mod api {
    pub mod collect;
    pub mod website;
    pub mod websites;
}
