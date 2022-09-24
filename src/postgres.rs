use std::{sync::Arc, time::Duration};

use tokio::sync::{OnceCell, RwLock, RwLockReadGuard};
use tokio_postgres::{types::Type, Config, Error, NoTls, Row, Statement};

/// Postgres client wrapper that monitors the connection and will reconnect on failure.
#[derive(Debug, Clone)]
pub struct DbReconnector(Arc<RwLock<Client>>);

impl DbReconnector {
    /// Connects to database using the given `config`.
    /// Creates the database if it doesn't exist.
    ///
    /// Returns `Ok(_)` if the initial connection is successful.
    ///
    /// If the connection later fails reconnection will automatically be attempted.
    pub async fn connect(mut config: Config) -> Result<Self, Error> {
        if config.get_connect_timeout().is_none() {
            config.connect_timeout(Duration::from_secs(10));
        }

        let (client, connection) = config.connect(NoTls).await?;

        let client = Arc::new(RwLock::new(Client::new(client)));
        let client_ref = Arc::downgrade(&client);

        tokio::spawn(async move {
            let mut active_connection = connection;
            while let Err(e) = active_connection.await {
                tracing::error!("postgres connection error: {}, trying to reconnect...", e);

                let client = match client_ref.upgrade() {
                    Some(c) => c,
                    // no client to reconnect
                    None => break,
                };
                // lock client during reconnection to block usage that would fail
                // while reconnection is happening
                let mut client_lock = client.write().await;

                // try to reconnect
                let (client, connection) = loop {
                    match config.connect(NoTls).await {
                        Ok(reconnect) => break reconnect,
                        Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
                    }
                };
                *client_lock = Client::new(client);
                active_connection = connection;
                tracing::info!("postgres reconnected");
            }
        });

        Ok(Self(client))
    }

    /// Returns a shared handle to the client.
    pub async fn client(&self) -> RwLockReadGuard<'_, Client> {
        self.0.read().await
    }
}

pub struct Client {
    inner: tokio_postgres::Client,
    get_website: OnceCell<Statement>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl Client {
    fn new(c: tokio_postgres::Client) -> Self {
        Client {
            inner: c,
            get_website: OnceCell::new(),
        }
    }

    pub async fn get_website(&self, id: i32) -> Result<Row, Error> {
        static QUERY: &str = "SELECT website_id, website_uuid, user_id, name, domain, share_id, created_at FROM website WHERE website_id = $1";
        let stmt = self
            .get_website
            .get_or_try_init(|| self.inner.prepare_typed(QUERY, &[Type::INT4]))
            .await?;
        self.inner.query_one(stmt, &[&id]).await
    }
}
