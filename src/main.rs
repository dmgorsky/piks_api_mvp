use std::error::Error;
use std::io::IsTerminal;
use std::sync::Arc;
use std::time::Duration;

use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderValue, Method};
use axum::Router;
use bb8::{ManageConnection, Pool};
use dotenv::dotenv;
use surreal_bb8::temp::compiletime_with_config::SurrealConnectionManager;
use surreal_bb8::temp::config::Config;
use surrealdb::dbs::Capabilities;
use surrealdb::engine::remote::ws::Ws;
use surrealdb::opt::auth::Root;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tracing::log::{error, info};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::env_config::EnvConfig;
use crate::router::create_router;

mod env_config;
mod error;
mod handler;
mod jwt_auth;
mod model;
mod responses;
pub mod router;
mod token;
// pub mod application;
pub mod data;

#[derive(Clone, Debug)]
pub struct AppContext {
    surreal_connection_pool: Arc<Pool<SurrealConnectionManager<Ws>>>,
    env: EnvConfig,
    redis_client: redis::Client,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env() // 'RUST_LOG'
                .unwrap_or_else(|_| "piks_api=debug,tower_http=debug".into()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::stderr().is_terminal())
                .with_writer(std::io::stdout /*stderr*/)
                .with_span_events(FmtSpan::CLOSE),
        )
        .init();

    dotenv().ok();

    let env_config = EnvConfig::init();

    let config = Config::new()
        .capabilities(Capabilities::default().with_guest_access(true))
        .strict();

    let db_url = env_config.database_url.clone();
    let sur_mgr: SurrealConnectionManager<Ws> =
        SurrealConnectionManager::new(db_url.as_str(), config);
    let sur_db = sur_mgr.connect().await.unwrap();
    sur_db
        .signin(Root {
            username: "root",
            password: "root",
        })
        .await?;
    sur_db.use_ns("test").use_db("test").await.unwrap();

    let pool = Pool::builder()
        .connection_timeout(Duration::from_secs(5))
        .retry_connection(true)
        .build(sur_mgr)
        .await
        .expect("build error");
    let shared_pool = Arc::new(pool);

    let surrealdb_connection = shared_pool.get().await.expect("pool error");
    match surrealdb_connection.health().await {
        Ok(_) => info!("Connected to surrealDB!"),
        Err(_) => error!("Not connected to surrealDB"),
    }

    let redis_client = match redis::Client::open(env_config.redis_url.to_owned()) {
        Ok(client) => {
            info!("Connected to redis!");
            client
        }
        Err(e) => {
            error!("Error connecting to Redis: {}", e);
            std::process::exit(1);
        }
    };

    let app_state = AppContext {
        surreal_connection_pool: Arc::clone(&shared_pool),
        env: env_config.clone(),
        redis_client: redis_client.clone(),
    };
    let cors = CorsLayer::new()
        .allow_origin(env_config.client_origin.parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
        .allow_credentials(true)
        .allow_headers([AUTHORIZATION, ACCEPT, CONTENT_TYPE]);

    let app: Router = create_router(Arc::new(app_state))
        // .with_state(Arc::new(app_state))
        .layer(cors)
        .layer(TimeoutLayer::new(Duration::from_secs(30)));
    println!("Listening at http://0.0.0.0:8080");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}
