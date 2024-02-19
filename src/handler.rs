use std::sync::Arc;

use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::http::{header, HeaderMap, Response};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use chrono::Utc;
use rand_core::OsRng;
use redis::AsyncCommands;
use serde_json::json;
use time::Duration;
use tracing::log::info;

use crate::data::users_repository::*;
use crate::error::PiksHttpError;
use crate::error::PiksHttpError::*;
use crate::jwt_auth::JWTAuthMiddleware;
use crate::model::LoginUserSchema;
use crate::{
    model::{RegisterUserSchema, User},
    responses::FilteredUser,
    token::{self, TokenDetails},
    AppContext,
};

fn filter_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id_for_token.to_string(),
        name: user.name.to_owned(),
        email: user.email.to_owned(),
        role: user.role.to_owned(),
        photo: user.photo.to_owned(),
        verified: user.verified,
        createdAt: user.created_at.unwrap(),
        updatedAt: user.updated_at.unwrap(),
    }
}

fn generate_token(
    user_id: uuid::Uuid,
    max_age: i64,
    private_key: String,
) -> Result<TokenDetails, (StatusCode, Json<serde_json::Value>)> {
    token::generate_jwt_token(user_id, max_age, private_key)
        .map_err(|e| PiksHttpError::ErrorGeneratingToken(e).into())
}

async fn save_token_data_to_redis(
    context: &Arc<AppContext>,
    token_details: &TokenDetails,
    max_age: i64,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let mut redis_client = context
        .redis_client
        .get_async_connection()
        .await
        .map_err(|e| RedisError(e).into())?;
    redis_client
        .set_ex(
            token_details.token_uuid.to_string(),
            token_details.user_id.to_string(),
            (max_age * 60) as u64,
        )
        .await
        .map_err(|e| UnprocessableEntity(e).into())?;
    Ok(())
}

#[tracing::instrument(level = "debug", skip(context))]
pub async fn register_user_handler(
    State(context): State<Arc<AppContext>>,
    Json(body): Json<RegisterUserSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let users_repo = UsersRepository::prepare(&context);
    let user: Option<User> = users_repo.get_by_email(&body.email).await?;
    if user.is_some_and(|contents| contents.email != "") {
        return Err(UserAlreadyExists.into());
    }

    let salt = SaltString::generate(&mut OsRng);

    let hashed_password = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| ErrorHashingPassword(Box::new(e)).into())
        .map(|hash| hash.to_string())?;

    let user_to_create = User {
        id: None,
        id_for_token: uuid::Uuid::new_v4(),
        name: body.name,
        email: body.email,
        password: hashed_password,
        role: "user".to_string(),
        photo: "".to_string(),
        verified: false,
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
    };

    let _created_user_record: Option<User> = users_repo.create_user(&user_to_create).await?;

    let user_response = json!({
        "status": "success",
        "user": filter_user_record(&user_to_create),
    });

    Ok(Json(user_response))
}

#[tracing::instrument(level = "debug", skip(context, body))]
pub async fn login_user_handler(
    State(context): State<Arc<AppContext>>,
    Json(body): Json<LoginUserSchema>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let users_repo = UsersRepository::prepare(&context);
    let user: Option<User> = users_repo.get_by_email(&body.email).await?;
    let user = user.ok_or(WrongCredentials.into())?;

    //TODO check stored salt
    // answer: stored inside https://docs.rs/argon2/latest/argon2/struct.PasswordHash.html
    // answer2: even not needed
    let is_valid = match PasswordHash::new(&user.password) {
        Ok(parsed_hash) => Argon2::default()
            .verify_password(body.password.as_bytes(), &parsed_hash)
            .map_or(false, |_| true),
        Err(_) => false,
    };

    if !is_valid {
        let error_response = json!( {
            "status": "failure",
            "message": "Invalid email or password".to_string(),
        });
        return Err((StatusCode::BAD_REQUEST, Json(error_response)));
    }

    let access_token_details = generate_token(
        user.id_for_token,
        context.env.access_token_max_age,
        context.env.access_token_private_key.to_owned(),
    )?;

    let refresh_token_details = generate_token(
        user.id_for_token,
        context.env.refresh_token_max_age,
        context.env.refresh_token_private_key.to_owned(),
    )?;

    save_token_data_to_redis(
        &context,
        &access_token_details,
        context.env.access_token_max_age,
    )
    .await?;
    save_token_data_to_redis(
        &context,
        &refresh_token_details,
        context.env.refresh_token_max_age,
    )
    .await?;

    let access_cookie = Cookie::build((
        "access_token",
        access_token_details.token.clone().unwrap_or_default(),
    ))
    .path("/")
    .max_age(Duration::minutes(context.env.access_token_max_age * 60))
    .same_site(SameSite::Lax)
    .http_only(true);

    let refresh_cookie = Cookie::build((
        "refresh_token",
        refresh_token_details.token.clone().unwrap_or_default(),
    ))
    .path("/")
    .max_age(Duration::minutes(context.env.refresh_token_max_age * 60))
    .same_site(SameSite::Lax)
    .http_only(true);

    let logged_in_cookie = Cookie::build(("logged_in", "true"))
        .path("/")
        .max_age(Duration::minutes(context.env.access_token_max_age * 60))
        .same_site(SameSite::Lax)
        .http_only(false);

    let mut response = Response::new(
        json!({
            "status": "success",
            "access_token": access_token_details.token.unwrap()
        })
        .to_string(),
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        access_cookie.to_string().parse().unwrap(),
    );
    headers.insert(
        header::SET_COOKIE,
        refresh_cookie.to_string().parse().unwrap(),
    );
    headers.insert(
        header::SET_COOKIE,
        logged_in_cookie.to_string().parse().unwrap(),
    );
    response.headers_mut().extend(headers);

    Ok(response)
}

#[tracing::instrument(level = "debug", skip(context))]
pub async fn refresh_access_token_handler(
    cookie_jar: CookieJar,
    State(context): State<Arc<AppContext>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let refresh_token = cookie_jar
        .get("refresh_token")
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| CouldNotRefreshToken.into())?;

    let refresh_token_details = match token::verify_jwt_token(
        context.env.refresh_token_public_key.to_owned(),
        &refresh_token,
    ) {
        Ok(token_details) => token_details,
        Err(e) => return Err(CouldNotVerifyRefreshToken(e).into()),
    };

    let mut redis_client = context
        .redis_client
        .get_async_connection()
        .await
        .map_err(|e| RedisError(e).into())?;

    let redis_token_user_id = redis_client
        .get::<_, String>(refresh_token_details.token_uuid.to_string())
        .await
        .map_err(|_| InvalidTokenExpiredSession.into())?;

    let user_id_uuid = uuid::Uuid::parse_str(&redis_token_user_id)
        .map_err(|_| InvalidTokenExpiredSession.into())?;

    let users_repo = UsersRepository::prepare(&context);
    let user = users_repo.get_by_id(user_id_uuid).await?;
    let user = user.ok_or_else(|| TokenUserNotFound.into())?;

    let access_token_details = generate_token(
        user.id_for_token,
        context.env.access_token_max_age,
        context.env.access_token_private_key.to_owned(),
    )?;

    save_token_data_to_redis(
        &context,
        &access_token_details,
        context.env.access_token_max_age,
    )
    .await?;

    let access_cookie = Cookie::build((
        "access_token",
        access_token_details.token.clone().unwrap_or_default(),
    ))
    .path("/")
    .max_age(Duration::minutes(context.env.access_token_max_age * 60))
    .same_site(SameSite::Lax)
    .http_only(true);

    let logged_in_cookie = Cookie::build(("logged_in", "true"))
        .path("/")
        .max_age(Duration::minutes(context.env.access_token_max_age * 60))
        .same_site(SameSite::Lax)
        .http_only(false);

    let mut response = Response::new(
        json!({"status": "success", "access_token": access_token_details.token.unwrap()})
            .to_string(),
    );

    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        access_cookie.to_string().parse().unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        logged_in_cookie.to_string().parse().unwrap(),
    );

    response.headers_mut().extend(headers);
    Ok(response)
}

#[tracing::instrument(level = "debug", skip(context))]
pub async fn logout_handler(
    cookie_jar: CookieJar,
    Extension(auth_guard): Extension<JWTAuthMiddleware>,
    State(context): State<Arc<AppContext>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let refresh_token = cookie_jar
        .get("refresh_token")
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| InvalidTokenExpiredSession.into())?;

    let refresh_token_details = match token::verify_jwt_token(
        context.env.refresh_token_public_key.to_owned(),
        &refresh_token,
    ) {
        Ok(token_details) => token_details,
        Err(e) => {
            let error_response = json!({
                "status": "fail",
                "message": format_args!("{:?}", e)
            });
            return Err((StatusCode::UNAUTHORIZED, Json(error_response)));
        }
    };

    let mut redis_client = context
        .redis_client
        .get_async_connection()
        .await
        .map_err(|e| RedisError(e).into())?;

    redis_client
        .del(&[
            refresh_token_details.token_uuid.to_string(),
            auth_guard.access_token_uuid.to_string(),
        ])
        .await
        .map_err(|e| RedisError(e).into())?;

    let access_cookie = Cookie::build(("access_token", ""))
        .path("/")
        .max_age(time::Duration::minutes(-1))
        .same_site(SameSite::Lax)
        .http_only(true);
    let refresh_cookie = Cookie::build(("refresh_token", ""))
        .path("/")
        .max_age(time::Duration::minutes(-1))
        .same_site(SameSite::Lax)
        .http_only(true);

    let logged_in_cookie = Cookie::build(("logged_in", "true"))
        .path("/")
        .max_age(time::Duration::minutes(-1))
        .same_site(SameSite::Lax)
        .http_only(false);

    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        access_cookie.to_string().parse().unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        refresh_cookie.to_string().parse().unwrap(),
    );
    headers.append(
        header::SET_COOKIE,
        logged_in_cookie.to_string().parse().unwrap(),
    );

    let mut response = Response::new(json!({"status": "success"}).to_string());
    response.headers_mut().extend(headers);
    Ok(response)
}

#[tracing::instrument(level = "debug")]
pub async fn get_me_handler(
    Extension(jwtauth): Extension<JWTAuthMiddleware>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let json_response = json!({
        "status":  "success",
        "data": serde_json::json!({
            "user": filter_user_record(&jwtauth.user)
        })
    });

    Ok(Json(json_response))
}

//
//
// utility playground
//
#[test]
fn check_pwd() {
    let old_pwd = "$argon2id$v=19$m=19456,t=2,p=1$9AsP6slYGxninrDicZGtWA$Ha5bDCdB/Cst12jwF9AFxQdFnu6lIFAjQTj6VtChspM";
    let check = match PasswordHash::new(old_pwd) {
        Ok(parsed_hash) => {
            dbg!(&parsed_hash);
            // dbg!(&parsed_hash.salt.unwrap().as_str());
            Argon2::default()
                .verify_password("password123".as_bytes(), &parsed_hash)
                .map_or(false, |_| true)
        }
        Err(_) => {
            println!("unable to parse");
            false
        }
    };
    assert_eq!(check, true);
}
