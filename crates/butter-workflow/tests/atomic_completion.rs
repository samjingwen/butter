//! Oracle: completion and domain writes share the atomic runner's disposition.
//! A separate completion transaction would expose a succeeded job before the
//! domain transaction commits, and would fail the explicit rollback assertions.

use butter_workflow::jobs::{JobLeaseIdentity, get_job_by_id};
use butter_workflow::{PgAtomicError, run_atomic};
use runledger_test_support::{setup_ephemeral_pool, teardown_ephemeral_pool};

#[path = "atomic_completion/boundaries.rs"]
mod boundaries;
#[path = "atomic_completion/faults.rs"]
mod faults;
#[path = "atomic_completion/fixture.rs"]
mod fixture;
#[path = "atomic_completion/lifecycle.rs"]
mod lifecycle;
mod support;
#[path = "atomic_completion/workflows.rs"]
mod workflows;

type Failure = Box<dyn std::error::Error + Send + Sync>;

#[tokio::test]
async fn success_and_domain_writes_commit_or_roll_back_together() {
    let (pool, database) = setup_ephemeral_pool("atomic_completion_disposition", 4).await;
    let profiled = support::profiled_database(&pool).await;
    support::register_test_job_definition(&pool, "test.atomic.completion").await;
    sqlx::query("CREATE TABLE completion_audit (value integer PRIMARY KEY)")
        .execute(&pool)
        .await
        .expect("create domain table");
    for (value, commit) in [(1_i32, true), (2, false)] {
        let job_id = support::enqueue_test_job(
            &pool,
            "test.atomic.completion",
            None,
            &serde_json::json!({}),
        )
        .await;
        let job = support::claim_one_job(&pool, "completion-worker").await;
        assert_eq!(job.id, job_id);
        let identity =
            JobLeaseIdentity::new(job.id, job.run_number, job.attempt, "completion-worker");
        let result = run_atomic(&profiled, async |scope| {
            let mut queue = scope.queue();
            let (domain, completion) = queue
                .complete_job_success(identity, None, async |sql| {
                    sqlx::query("INSERT INTO completion_audit VALUES ($1)")
                        .bind(value)
                        .execute(sql.executor())
                        .await?;
                    Ok::<_, Failure>(value)
                })
                .await
                .expect("compose domain write and native success");
            assert_eq!(domain, value);
            assert_eq!(completion.job_id, job_id);
            let visible = get_job_by_id(&pool, None, job_id)
                .await
                .expect("read job independently")
                .expect("job exists");
            assert_eq!(visible.status.as_db_value(), "LEASED");
            let writes: i64 =
                sqlx::query_scalar("SELECT count(*) FROM completion_audit WHERE value=$1")
                    .bind(value)
                    .fetch_one(&pool)
                    .await
                    .expect("read domain writes independently");
            assert_eq!(
                writes, 0,
                "both outputs are provisional before outer commit"
            );
            if commit {
                Ok(())
            } else {
                Err("reject entire operation")
            }
        })
        .await;
        if commit {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(PgAtomicError::Rejected("reject entire operation"))
            ));
        }
        let status: String = sqlx::query_scalar("SELECT status::text FROM job_queue WHERE id=$1")
            .bind(job_id)
            .fetch_one(&pool)
            .await
            .expect("read final native status");
        assert_eq!(status, if commit { "SUCCEEDED" } else { "LEASED" });
        let writes: i64 =
            sqlx::query_scalar("SELECT count(*) FROM completion_audit WHERE value=$1")
                .bind(value)
                .fetch_one(&pool)
                .await
                .expect("read final domain state");
        let events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM job_events WHERE job_id=$1 AND event_type='SUCCEEDED'",
        )
        .bind(job_id)
        .fetch_one(&pool)
        .await
        .expect("read completion event");
        assert_eq!((writes, events), (i64::from(commit), i64::from(commit)));
    }
    profiled.pool().close().await;
    teardown_ephemeral_pool(pool, database).await;
}

#[tokio::test]
async fn stale_completion_never_invokes_domain_callback() {
    let (pool, database) = setup_ephemeral_pool("atomic_completion_stale", 4).await;
    let profiled = support::profiled_database(&pool).await;
    support::register_test_job_definition(&pool, "test.atomic.stale").await;
    support::enqueue_test_job(&pool, "test.atomic.stale", None, &serde_json::json!({})).await;
    let job = support::claim_one_job(&pool, "completion-worker").await;
    let stale = JobLeaseIdentity::new(job.id, job.run_number + 1, job.attempt, "completion-worker");
    let called = std::sync::atomic::AtomicBool::new(false);
    let result = run_atomic(&profiled, async |scope| {
        scope
            .queue()
            .complete_job_success(stale, None, async |_sql| {
                called.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, Failure>(())
            })
            .await
    })
    .await;
    assert!(result.is_err());
    assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
    let row = get_job_by_id(&pool, None, job.id)
        .await
        .expect("read job")
        .expect("job exists");
    assert_eq!(row.status.as_db_value(), "LEASED");
    profiled.pool().close().await;
    teardown_ephemeral_pool(pool, database).await;
}
