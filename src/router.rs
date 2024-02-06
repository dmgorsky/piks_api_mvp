use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{middleware, Json, Router};

use crate::handler::{
    get_me_handler, login_user_handler, logout_handler, refresh_access_token_handler,
    register_user_handler,
};
use crate::jwt_auth::auth;
use crate::AppContext;

pub fn create_router(app_state: Arc<AppContext>) -> Router
// where T: Clone + Send + Sync + 'static
{
    Router::new()
        .route("/api/healthcheck", get(health_check_handler))
        .route("/api/auth/register", post(register_user_handler))
        .route("/api/auth/login", post(login_user_handler))
        .route("/api/auth/refresh", get(refresh_access_token_handler))
        .route(
            "/api/auth/logout",
            get(logout_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .route(
            "/api/users/me",
            get(get_me_handler)
                .route_layer(middleware::from_fn_with_state(app_state.clone(), auth)),
        )
        .with_state(app_state)
    // .route("/api/users",
    //        post(create_user_command)
    //            .get(get_all_users_query),
    // )
    // .route("/api/users/:id",
    //        get(get_user_by_id_query)
    //            .put(update_user_command)
    //            .delete(delete_user_command),
    // )
}

/// health check (for k8s)
/// checks surreal db (via axum's AppState: `AppContext`)
/// connection pool's health
#[tracing::instrument(level = "debug", skip(context))]
pub async fn health_check_handler(State(context): State<Arc<AppContext>>) -> impl IntoResponse {
    let connection = context.surreal_connection_pool.get().await;
    if connection.is_err() {
        let json_response = serde_json::json!({
        "status": "unhealthy",
        "message": "connection pool is not ready"
            });
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json_response));
    }
    let check_connection = connection.unwrap().health().await;

    if check_connection.is_err() {
        let json_response = serde_json::json!({
            "status": "unhealthy",
            "message": "connection pool is not ready"
        });
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json_response));
    } else if context.redis_client.get_connection().is_err() {
        let json_response = serde_json::json!({
            "status": "unhealthy",
            "message": "not connected to redis"
        });
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json_response));
    } else {
        let json_response = serde_json::json!({
            "status": "success",
            "message": "alive"
        });
        return (StatusCode::OK, Json(json_response));
    }
}
