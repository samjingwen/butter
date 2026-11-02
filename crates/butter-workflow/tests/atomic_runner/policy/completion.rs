//! Oracle: completion inherits the selected recoverable/fail-fast policy and
//! preserves the same consumer error and native outcome semantics.

use super::*;
use butter_workflow::jobs::{JobContinuationUpdate, JobFailureUpdate, JobLeaseIdentity};
use runledger_core::jobs::{JobFailureKind, JobStatus};

#[tokio::test]
async fn completion_methods_preserve_policy_and_send_composition() {
    for fast in [false, true] {
        let (pool, database) = setup_ephemeral_pool("completion_policy", 4).await;
        let profiled = support::profiled_database(&pool).await;
        support::register_test_job_definition(&pool, "test.atomic.completion_policy").await;
        sqlx::query("CREATE TABLE completion_policy_audit (id uuid PRIMARY KEY)")
            .execute(&pool)
            .await
            .expect("application table");
        for mode in 0..3 {
            let id = support::enqueue_test_job(
                &pool,
                "test.atomic.completion_policy",
                None,
                &serde_json::json!({}),
            )
            .await;
            let job = support::claim_one_job(&pool, "policy-worker").await;
            assert_eq!(job.id, id);
            let lease = JobLeaseIdentity::new(job.id, job.run_number, job.attempt, "policy-worker");
            let work = async |scope: butter_workflow::PgPolicyIntentScope<'_, (), Policy>| {
                let mut queue = scope.queue();
                let domain = async |sql: &mut butter_workflow::PgScopedSql<'_>| {
                    sqlx::query("INSERT INTO completion_policy_audit VALUES ($1)")
                        .bind(job.id)
                        .execute(sql.executor())
                        .await?;
                    Ok::<_, ConsumerError>(())
                };
                match mode {
                    0 => {
                        queue.complete_job_success(lease, None, domain).await?;
                    }
                    1 => {
                        let update = JobContinuationUpdate {
                            delay: std::time::Duration::from_secs(60),
                            progress_done: None,
                            progress_total: None,
                            checkpoint: None,
                        };
                        queue
                            .complete_job_continuation(lease, &update, domain)
                            .await?;
                    }
                    _ => {
                        let update = JobFailureUpdate::new(
                            JobFailureKind::Terminal,
                            "test.failure",
                            "synthetic",
                            None,
                        );
                        queue.complete_job_failure(lease, &update, domain).await?;
                    }
                }
                Ok(())
            };
            fn send<T: Send>(value: T) -> T {
                value
            }
            let result = if fast {
                send(run_atomic_fail_fast_with(&profiled, &Policy, work)).await
            } else {
                send(run_atomic_with(&profiled, &Policy, work)).await
            };
            result.unwrap_or_else(|error| {
                panic!("completion policy failure: {:?}", error.retained_cause())
            });
            let effects: i64 =
                sqlx::query_scalar("SELECT count(*) FROM completion_policy_audit WHERE id=$1")
                    .bind(job.id)
                    .fetch_one(&pool)
                    .await
                    .expect("domain effect");
            assert_eq!(effects, 1);
            let row = butter_workflow::jobs::get_job_by_id(&pool, None, job.id)
                .await
                .expect("read job")
                .expect("exists");
            assert_eq!(
                row.status,
                match mode {
                    0 => JobStatus::Succeeded,
                    1 => JobStatus::Pending,
                    _ => JobStatus::DeadLettered,
                }
            );
        }
        profiled.pool().close().await;
        teardown_ephemeral_pool(pool, database).await;
    }
}

#[tokio::test]
async fn caught_completion_rejection_cannot_resurrect_a_fail_fast_transaction() {
    for fast in [false, true] {
        let (pool, database) = setup_ephemeral_pool("completion_policy_rejection", 4).await;
        let profiled = support::profiled_database(&pool).await;
        support::register_test_job_definition(&pool, "test.atomic.completion_rejection").await;
        support::enqueue_test_job(
            &pool,
            "test.atomic.completion_rejection",
            None,
            &serde_json::json!({}),
        )
        .await;
        let job = support::claim_one_job(&pool, "policy-worker").await;
        sqlx::query("CREATE TABLE completion_policy_audit (id integer PRIMARY KEY)")
            .execute(&pool)
            .await
            .expect("application table");
        let work = async |scope: butter_workflow::PgPolicyIntentScope<'_, (), Policy>| {
            let mut queue = scope.queue();
            queue
                .execute(sqlx::query(
                    "INSERT INTO completion_policy_audit VALUES (1)",
                ))
                .await?;
            let rejected = queue
                .complete_job_success(
                    JobLeaseIdentity::new(job.id, job.run_number, job.attempt, "policy-worker"),
                    None,
                    async |sql| {
                        sqlx::query("INSERT INTO completion_policy_audit VALUES (2)")
                            .execute(sql.executor())
                            .await?;
                        Err::<(), ConsumerError>(sqlx::Error::RowNotFound.into())
                    },
                )
                .await;
            assert!(matches!(
                rejected,
                Err(ConsumerError::Sql(sqlx::Error::RowNotFound))
            ));
            Ok(())
        };
        let result = if fast {
            run_atomic_fail_fast_with(&profiled, &Policy, work).await
        } else {
            run_atomic_with(&profiled, &Policy, work).await
        };
        assert_eq!(result.is_err(), fast);
        let values: Vec<i32> =
            sqlx::query_scalar("SELECT id FROM completion_policy_audit ORDER BY id")
                .fetch_all(&pool)
                .await
                .expect("read committed effects");
        assert_eq!(values, if fast { vec![] } else { vec![1] });
        profiled.pool().close().await;
        teardown_ephemeral_pool(pool, database).await;
    }
}
