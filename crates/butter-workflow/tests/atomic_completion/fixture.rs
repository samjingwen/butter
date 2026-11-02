use butter_workflow::jobs::{JobLeaseIdentity, JobQueueRecord, claim_jobs, get_job_by_id};
use butter_workflow::{DbPool, PgScopedSql, RunledgerDatabase};
use runledger_test_support::{EphemeralDatabase, setup_ephemeral_pool, teardown_ephemeral_pool};
use sqlx::types::Uuid;

use super::{Failure, support};

pub const WORKER: &str = "completion-worker";
pub const JOB_TYPE: &str = "test.atomic.lifecycle";

pub struct Fixture {
    pub pool: DbPool,
    pub profiled: RunledgerDatabase,
    database: EphemeralDatabase,
}

impl Fixture {
    pub async fn new(name: &str) -> Self {
        let (pool, database) = setup_ephemeral_pool(name, 5).await;
        let profiled = support::profiled_database(&pool).await;
        let version: String = sqlx::query_scalar("SHOW server_version")
            .fetch_one(&pool)
            .await
            .expect("read PostgreSQL version");
        let major: i32 =
            sqlx::query_scalar("SELECT current_setting('server_version_num')::int / 10000")
                .fetch_one(&pool)
                .await
                .expect("read PostgreSQL major");
        assert_eq!(major, 18);
        eprintln!("atomic completion PostgreSQL {version}");
        support::register_test_job_definition(&pool, JOB_TYPE).await;
        sqlx::query("CREATE TABLE completion_effects (job_id uuid PRIMARY KEY, value integer NOT NULL CHECK (value > 0))")
            .execute(&pool).await.expect("create domain table");
        Self {
            pool,
            profiled,
            database,
        }
    }

    pub async fn claimed(&self, lease_seconds: i32) -> JobQueueRecord {
        let id =
            support::enqueue_test_job(&self.pool, JOB_TYPE, None, &serde_json::json!({})).await;
        let job = claim_jobs(&self.pool, WORKER, lease_seconds, 1)
            .await
            .expect("claim job")
            .pop()
            .expect("one claim");
        assert_eq!(job.id, id);
        job
    }

    pub async fn effects(&self, id: Uuid) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM completion_effects WHERE job_id=$1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .expect("read domain effects")
    }

    pub async fn job(&self, id: Uuid) -> JobQueueRecord {
        get_job_by_id(&self.pool, None, id)
            .await
            .expect("read job")
            .expect("job exists")
    }

    pub async fn close(self) {
        self.profiled.pool().close().await;
        teardown_ephemeral_pool(self.pool, self.database).await;
    }
}

pub fn identity(job: &JobQueueRecord) -> JobLeaseIdentity<'static> {
    JobLeaseIdentity::new(job.id, job.run_number, job.attempt, WORKER)
}

pub async fn write(sql: &mut PgScopedSql<'_>, id: Uuid) -> Result<(), Failure> {
    sqlx::query("INSERT INTO completion_effects VALUES ($1, 1)")
        .bind(id)
        .execute(sql.executor())
        .await?;
    Ok(())
}
