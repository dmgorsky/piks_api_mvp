use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};

use crate::{model::User, token, AppContext};

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub status: &'static str,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWTAuthMiddleware {
    pub user: User,
    pub access_token_uuid: uuid::Uuid,
}

pub async fn auth(
    cookie_jar: CookieJar,
    State(context): State<Arc<AppContext>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let access_token = cookie_jar
        .get("access_token")
        .map(|cookie| cookie.value().to_string())
        .or_else(|| {
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|auth_header| auth_header.to_str().ok())
                .and_then(|auth_value| {
                    if auth_value.starts_with("Bearer ") {
                        Some(auth_value[7..].to_owned())
                    } else {
                        None
                    }
                })
        });
    let access_token = access_token.ok_or_else(|| {
        let error_response = ErrorResponse {
            status: "failure",
            message: "You are not logged in, please provide token".to_string(),
        };
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;

    let access_token_details = match token::verify_jwt_token(
        context.env.access_token_public_key.to_owned(),
        &access_token,
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            let error_response = ErrorResponse {
                status: "failure",
                message: format!("{:?}", e),
            };
            return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
        }
    };

    let access_token_uuid = uuid::Uuid::parse_str(&access_token_details.token_uuid.to_string())
        .map_err(|_| {
            let error_response = ErrorResponse {
                status: "failure",
                message: "Invalid token".to_string(),
            };
            (StatusCode::UNAUTHORIZED, Json(error_response))
        })?;

    let mut redis_client = context
        .redis_client
        .get_async_connection()
        .await
        .map_err(|e| {
            let error_response = ErrorResponse {
                status: "error",
                message: format!("Redis error: {}", e),
            };
            (StatusCode::UNAUTHORIZED, Json(error_response))
        })?;
    let _redis_token_user_id = redis_client
        .get::<_, String>(access_token_uuid.clone().to_string())
        .await
        .map_err(|_| {
            let error_response = ErrorResponse {
                status: "error",
                message: "Token is invalid or session has expired".to_string(),
            };
            (StatusCode::UNAUTHORIZED, Json(error_response))
        })?;
    let surr_client = context.surreal_connection_pool.get().await.map_err(|e| {
        let error_response = ErrorResponse {
            status: "error",
            message: format!("SurrealDB connection pool error: {}", e),
        };
        (StatusCode::UNAUTHORIZED, Json(error_response))
    })?;
    let user = surr_client
        .select((
            "users",
            surrealdb::sql::Uuid::from(access_token_details.user_id),
        ))
        .await
        .map_err(|_| {
            let error_response = ErrorResponse {
                status: "failure",
                message: "The user belonging to this token not found in database".to_string(),
            };
            (StatusCode::UNAUTHORIZED, Json(error_response))
        })?
        .unwrap();
    req.extensions_mut().insert(JWTAuthMiddleware {
        user,
        access_token_uuid,
    });
    Ok(next.run(req).await)
}
