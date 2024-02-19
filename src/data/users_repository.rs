use std::sync::Arc;

use axum::http::StatusCode;
use axum::Json;
use bb8::{Pool, PooledConnection};
use serde_json::Value;
use surreal_bb8::temp::compiletime_with_config::SurrealConnectionManager;
use surrealdb::engine::remote::ws::Ws;

use crate::error::PiksHttpError::{
    ConnectionPoolError, DatabaseError, PooledConnectionManagerError,
};
use crate::model::User;
use crate::AppContext;

pub struct UsersRepository<'repo> {
    table_name: &'repo str,
    connection_pool: Arc<Pool<SurrealConnectionManager<Ws>>>,
}

impl<'repo> UsersRepository<'repo> {
    pub fn prepare(context: &Arc<AppContext>) -> Self {
        UsersRepository {
            table_name: "users",
            connection_pool: Arc::clone(&context.surreal_connection_pool),
        }
    }

    async fn prepare_surreal_client(
        &self,
    ) -> Result<PooledConnection<SurrealConnectionManager<Ws>>, (StatusCode, Json<Value>)> {
        let surr_client = self
            .connection_pool
            .get()
            .await
            .map_err(|e| PooledConnectionManagerError(e.to_string()).into())?;
        let _ = surr_client
            .use_ns("test")
            .use_db("test")
            .await
            .map_err(|e| ConnectionPoolError(e).into())?;
        Ok(surr_client)
    }

    pub async fn get_by_id(
        &self,
        id: uuid::Uuid,
    ) -> Result<Option<User>, (StatusCode, Json<Value>)> {
        let surr_client = self.prepare_surreal_client().await?;
        let user: Option<User> = surr_client
            .select((self.table_name, surrealdb::sql::Uuid::from(id)))
            .await
            .map_err(|e| DatabaseError(e).into())?;
        Ok(user)
    }

    pub async fn get_by_email(
        &self,
        email: &str,
    ) -> Result<Option<User>, (StatusCode, Json<Value>)> {
        let surr_client = self.prepare_surreal_client().await?;
        let user: Option<User> = surr_client
            .query("select * from type::table($table) where email=$email")
            .bind(("table", self.table_name))
            .bind(("email", email.to_owned().to_ascii_lowercase()))
            .await
            .map_err(|e| DatabaseError(e).into())?
            .take(0)
            .map_err(|e| DatabaseError(e).into())?;
        Ok(user)
    }

    pub async fn create_user(
        &self,
        user_record: &User,
    ) -> Result<Option<User>, (StatusCode, Json<Value>)> {
        let surr_client = self.prepare_surreal_client().await?;
        let created_user_record: Option<User> = surr_client
            .create((
                self.table_name,
                surrealdb::sql::Id::from(surrealdb::sql::Uuid::from(user_record.id_for_token)),
            ))
            .content(&user_record)
            .await
            .map_err(|e| DatabaseError(e).into())?;
        Ok(created_user_record)
    }
}
