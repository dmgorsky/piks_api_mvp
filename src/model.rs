use chrono::prelude::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use surrealdb::sql::Thing;

#[derive(Debug, Deserialize)]
pub struct Record {
    #[allow(dead_code)]
    id: Thing,
}

// pub const USERS_TABLE: &str = "users";
//
// #[derive(Serialize, Deserialize, Clone, Debug)]
// pub struct UserId(RecordId);
// impl NewId for UserId {
//     const TABLE: &'static str = USERS_TABLE;
//
//     fn from_inner_id<T: Into<Id>>(inner_id: T) -> Self {
//         UserId(RecordId {
//             tb: Self::TABLE.to_string(),
//             id: inner_id.into(),
//         })
//     }
//
//     fn get_inner_string(&self) -> String {
//         self.0.id.to_string()
//     }
// }

#[allow(non_snake_case)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Thing>,
    #[serde(with = "uuid::serde::compact")]
    pub id_for_token: uuid::Uuid,
    pub name: String,
    pub email: String,
    pub password: String,
    // pub salt: String,
    pub role: String,
    pub photo: String,
    pub verified: bool,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterUserSchema {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginUserSchema {
    pub email: String,
    pub password: String,
}
