use std::io;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use butter_workflow::jobs::{
    JobEnqueueIntent, JobEnqueueIntentDisposition, record_job_enqueue_intent,
};
use butter_workflow::{CommitUnconfirmed, Error, RunledgerDatabase};
use runledger_core::jobs::JobType;
use runledger_test_support::{setup_ephemeral_pool, teardown_ephemeral_pool};
use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::types::Uuid;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

const JOB_TYPE: &str = "jobs.test.commit_acknowledgement";
const IDEMPOTENCY_KEY: &str = "durable-without-acknowledgement";

mod support;

// PostgreSQL v3 protocol frames. Both lengths include the four-byte length
// field but exclude the one-byte message type.
const FRONTEND_COMMIT: &[u8] = b"Q\0\0\0\x0bCOMMIT\0";
const BACKEND_COMMIT_COMPLETE: &[u8] = b"C\0\0\0\x0bCOMMIT\0";

struct CommitAcknowledgementDropProxy {
    pool: sqlx::PgPool,
    task: JoinHandle<io::Result<bool>>,
}

impl CommitAcknowledgementDropProxy {
    async fn connect(database_url: &str) -> Self {
        let (options, task) = Self::start(database_url).await;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("connect through commit acknowledgement proxy");
        Self { pool, task }
    }

    async fn connect_profiled(
        database_url: &str,
        profile: butter_workflow::PgSessionProfile,
    ) -> (Self, RunledgerDatabase) {
        let (options, task) = Self::start(database_url).await;
        // The protected pool must own the one proxied connection. The eager
        // constructor also opens a probe, so use its supported lazy equivalent.
        let database = RunledgerDatabase::connect_lazy(
            options,
            profile,
            PgPoolOptions::new().max_connections(1),
        )
        .expect("declare profiled proxy connection");
        (
            Self {
                pool: database.pool().clone(),
                task,
            },
            database,
        )
    }

    async fn start(database_url: &str) -> (PgConnectOptions, JoinHandle<io::Result<bool>>) {
        let target_options = PgConnectOptions::from_str(database_url)
            .expect("parse ephemeral PostgreSQL connection options")
            .ssl_mode(PgSslMode::Disable);
        let target = (
            target_options.get_host().to_owned(),
            target_options.get_port(),
        );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind commit acknowledgement proxy");
        let proxy_port = listener.local_addr().expect("proxy address").port();
        let task = tokio::spawn(proxy_one_connection(listener, target));
        (target_options.host("127.0.0.1").port(proxy_port), task)
    }

    async fn assert_acknowledgement_dropped(self) {
        self.pool.close().await;
        let dropped = timeout(Duration::from_secs(5), self.task)
            .await
            .expect("commit acknowledgement proxy must finish")
            .expect("commit acknowledgement proxy task must join")
            .expect("commit acknowledgement proxy must forward PostgreSQL traffic");
        assert!(
            dropped,
            "proxy must observe PostgreSQL commit completion before dropping the acknowledgement"
        );
    }
}

async fn proxy_one_connection(listener: TcpListener, target: (String, u16)) -> io::Result<bool> {
    let (client, _) = listener.accept().await?;
    let server = TcpStream::connect(target).await?;
    let (mut client_reader, mut client_writer) = client.into_split();
    let (mut server_reader, mut server_writer) = server.into_split();
    let commit_forwarded = Arc::new(AtomicBool::new(false));
    let upstream_commit_forwarded = Arc::clone(&commit_forwarded);

    let upstream = tokio::spawn(async move {
        let mut buffer = [0_u8; 8 * 1024];
        let mut protocol = Vec::new();
        loop {
            let read = client_reader.read(&mut buffer).await?;
            if read == 0 {
                server_writer.shutdown().await?;
                return Ok::<(), io::Error>(());
            }

            if !upstream_commit_forwarded.load(Ordering::Acquire) {
                protocol.extend_from_slice(&buffer[..read]);
                if contains_protocol_frame(&protocol, FRONTEND_COMMIT) {
                    // Arm the downstream before forwarding the complete COMMIT
                    // frame, so even a very fast server response cannot escape.
                    upstream_commit_forwarded.store(true, Ordering::Release);
                }
            }
            server_writer.write_all(&buffer[..read]).await?;
        }
    });

    let downstream = async {
        let mut buffer = [0_u8; 8 * 1024];
        let mut commit_response = Vec::new();
        loop {
            let read = server_reader.read(&mut buffer).await?;
            if read == 0 {
                client_writer.shutdown().await?;
                return Ok(false);
            }

            if commit_forwarded.load(Ordering::Acquire) {
                commit_response.extend_from_slice(&buffer[..read]);
                if contains_protocol_frame(&commit_response, BACKEND_COMMIT_COMPLETE) {
                    // PostgreSQL has completed COMMIT, but SQLx sees EOF instead
                    // of CommandComplete/ReadyForQuery.
                    client_writer.shutdown().await?;
                    return Ok(true);
                }
            }
            client_writer.write_all(&buffer[..read]).await?;
        }
    }
    .await;

    upstream.abort();
    let _ = upstream.await;
    downstream
}

fn contains_protocol_frame(buffer: &[u8], frame: &[u8]) -> bool {
    buffer.windows(frame.len()).any(|window| window == frame)
}

#[tokio::test]
async fn durable_commit_without_acknowledgement_remains_an_unknown_outcome() {
    let (pool, database) = setup_ephemeral_pool("postgres_commit_ack_lost", 2).await;
    let server_version = sqlx::query_scalar::<_, String>("SHOW server_version")
        .fetch_one(&pool)
        .await
        .expect("read PostgreSQL server_version");
    let server_version_num =
        sqlx::query_scalar::<_, i32>("SELECT current_setting('server_version_num')::int")
            .fetch_one(&pool)
            .await
            .expect("read PostgreSQL server_version_num");
    eprintln!(
        "commit acknowledgement regression PostgreSQL server_version={server_version}, \
         server_version_num={server_version_num}"
    );

    let proxy = CommitAcknowledgementDropProxy::connect(database.url()).await;
    let payload = json!({"event": "commit-ack-lost"});
    let intent = JobEnqueueIntent::new(JobType::new(JOB_TYPE), &payload, IDEMPOTENCY_KEY);
    let error = record_job_enqueue_intent(&proxy.pool, &intent)
        .await
        .expect_err("lost commit acknowledgement must not report success");

    let Error::CommitUnconfirmed(unconfirmed) = &error else {
        panic!("lost commit acknowledgement must remain a top-level unknown outcome")
    };
    assert_eq!(
        unconfirmed.operation(),
        "commit record job enqueue intent transaction"
    );
    assert_eq!(unconfirmed.sqlstate(), None);
    assert_eq!(CommitUnconfirmed::CODE, "db.transaction_commit_unconfirmed");
    proxy.assert_acknowledgement_dropped().await;

    let durable_intent_id: Uuid = sqlx::query_scalar(
        "SELECT id
         FROM job_enqueue_intents
         WHERE job_type = $1 AND idempotency_key = $2",
    )
    .bind(JOB_TYPE)
    .bind(IDEMPOTENCY_KEY)
    .fetch_one(&pool)
    .await
    .expect("independent connection must observe the committed intent");

    let recovered = record_job_enqueue_intent(&pool, &intent)
        .await
        .expect("idempotent reconciliation may safely repeat the intent");
    assert_eq!(recovered.intent_id, durable_intent_id);
    assert_eq!(recovered.disposition, JobEnqueueIntentDisposition::Existing);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*)
             FROM job_enqueue_intents
             WHERE job_type = $1 AND idempotency_key = $2",
        )
        .bind(JOB_TYPE)
        .bind(IDEMPOTENCY_KEY)
        .fetch_one(&pool)
        .await
        .expect("count durable intents"),
        1
    );

    teardown_ephemeral_pool(pool, database).await;
}

#[tokio::test]
async fn atomic_domain_and_job_completion_survive_a_lost_database_commit_reply() {
    use butter_workflow::jobs::{JobLeaseIdentity, get_job_by_id};
    use butter_workflow::{PgAtomicError, PgAtomicUncertainty, run_atomic};
    let (pool, fixture) = setup_ephemeral_pool("atomic_completion_commit_reply_lost", 4).await;
    let direct = support::profiled_database(&pool).await;
    support::register_test_job_definition(&pool, JOB_TYPE).await;
    let id = support::enqueue_test_job(&pool, JOB_TYPE, None, &json!({})).await;
    let job = support::claim_one_job(&pool, "completion-worker").await;
    assert_eq!(job.id, id);
    sqlx::query("CREATE TABLE completion_accounting (job_id uuid PRIMARY KEY)")
        .execute(&pool)
        .await
        .expect("create domain accounting");
    let (proxy, database) =
        CommitAcknowledgementDropProxy::connect_profiled(fixture.url(), direct.profile().clone())
            .await;
    let result = timeout(
        Duration::from_secs(10),
        run_atomic(&database, async |scope| {
            scope
                .queue()
                .complete_job_success(
                    JobLeaseIdentity::new(job.id, job.run_number, job.attempt, "completion-worker"),
                    None,
                    async |sql| {
                        sqlx::query("INSERT INTO completion_accounting VALUES ($1)")
                            .bind(job.id)
                            .execute(sql.executor())
                            .await?;
                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                    },
                )
                .await
        }),
    )
    .await
    .expect("completion must observe lost connection");
    assert!(
        matches!(result, Err(PgAtomicError::Uncertain(PgAtomicUncertainty::CommitUnconfirmed {
        output: ((), ref completion), ..
    })) if completion.job_id == job.id)
    );
    proxy.assert_acknowledgement_dropped().await;
    assert_eq!(
        get_job_by_id(&pool, None, job.id)
            .await
            .expect("independent job read")
            .expect("job exists")
            .status
            .as_db_value(),
        "SUCCEEDED"
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM completion_accounting WHERE job_id=$1")
            .bind(job.id)
            .fetch_one(&pool)
            .await
            .expect("independent accounting read");
    assert_eq!(
        count, 1,
        "both changes committed despite the missing acknowledgement"
    );
    direct.pool().close().await;
    teardown_ephemeral_pool(pool, fixture).await;
}
