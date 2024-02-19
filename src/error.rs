use std::error::Error;

use axum::{http::StatusCode, Json};
use redis::RedisError;
use serde_json::{json, Value};

// #[derive(thiserror::Error, Debug)]
// pub enum PiksAppError {
//     #[error("Error generating token: {0}")]
//     ErrorGeneratingToken(#[source] std::io::Error),
//     // InvalidToken,
//     // WrongCredentials,
//     // MissingCredentials,
//     // TokenCreation,
//     // InternalServerError,
//     // UserDoesNotExist,
//     // UserAlreadyExists,
// }

pub enum PiksHttpError {
    ErrorGeneratingToken(jsonwebtoken::errors::Error),
    RedisError(RedisError),
    UnprocessableEntity(RedisError),
    DatabaseError(surrealdb::Error),
    ConnectionPoolError(surrealdb::Error),
    // UnauthorizedConnectionPoolError(String),
    PooledConnectionManagerError(String),
    UserAlreadyExists,
    ErrorHashingPassword(Box<dyn Error>),
    WrongCredentials,
    // InvalidToken,
    InvalidTokenExpiredSession,
    TokenUserNotFound,
    CouldNotRefreshToken,
    CouldNotVerifyRefreshToken(jsonwebtoken::errors::Error),
}

// impl IntoResponse for PiksHttpError {
//     fn into_response(self) -> Response {
//         let (status_code, error_message) = match self {
//             PiksHttpError::ErrorGeneratingToken(e) => (
//                 StatusCode::INTERNAL_SERVER_ERROR,
//                 format!("Error generating token: {}", e),
//             ),
//             PiksHttpError::RedisError(e) => (
//                 StatusCode::INTERNAL_SERVER_ERROR,
//                 format!("Redis error: {}", e),
//             ),
//         };
//         (status_code, Json(json!({"error": error_message}))).into_response()
//     }
// }

impl Into<(axum::http::StatusCode, axum::Json<serde_json::Value>)> for PiksHttpError {
    fn into(self) -> (StatusCode, Json<Value>) {
        let (status_code, error_message) = match self {
            PiksHttpError::ErrorGeneratingToken(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error generating token: {}", e),
            ),
            PiksHttpError::RedisError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Redis error: {:?}", e),
            ),
            PiksHttpError::UnprocessableEntity(e) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Redis error: {}", e),
            ),
            PiksHttpError::DatabaseError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            ),
            PiksHttpError::ConnectionPoolError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Connection pool error: {}", e),
            ),
            // PiksHttpError::UnauthorizedConnectionPoolError(e) => (
            //     StatusCode::UNAUTHORIZED,
            //     format!("Connection pool error: {}", e),
            // ),
            PiksHttpError::PooledConnectionManagerError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Connection pool manager error: {}", e),
            ),
            PiksHttpError::UserAlreadyExists => (
                StatusCode::CONFLICT,
                "User with this email already exists".to_string(),
            ),
            PiksHttpError::ErrorHashingPassword(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error while hashing password: {}", e),
            ),
            PiksHttpError::WrongCredentials => (
                StatusCode::BAD_REQUEST,
                "Invalid email or password".to_string(),
            ),
            // PiksHttpError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            PiksHttpError::InvalidTokenExpiredSession => (
                StatusCode::UNAUTHORIZED,
                "Token is invalid or session has expired".to_string(),
            ),
            PiksHttpError::TokenUserNotFound => (
                StatusCode::UNAUTHORIZED,
                "The user belonging to this token no longer exists".to_string(),
            ),
            PiksHttpError::CouldNotRefreshToken => (
                StatusCode::FORBIDDEN,
                "Could not refresh access token".to_string(),
            ),
            PiksHttpError::CouldNotVerifyRefreshToken(e) => (
                StatusCode::UNAUTHORIZED,
                format!("Could not refresh access token: {}", e),
            ),
        };
        (
            status_code,
            Json(json!({"status": "error", "message": error_message})).into(),
        )
    }
}

// impl IntoResponse for PiksAppError {
//     fn into_response(self) -> Response {
//         let (status_code, error_message) = match self {
//             PiksAppError::InvalidToken => {},
//             PiksAppError::WrongCredentials => {},
//             PiksAppError::MissingCredentials => {},
//             PiksAppError::TokenCreation => {},
//             PiksAppError::InternalServerError => {StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"},
//             PiksAppError::UserDoesNotExist => {},
//             PiksAppError::UserAlreadyExists => {},
//         };
//             (status_code, Json(json!({"error": error_message}))).into_response()
//     }
// }
