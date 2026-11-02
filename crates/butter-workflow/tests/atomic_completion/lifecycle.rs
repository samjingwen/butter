//! Oracles: existing native continuation/failure semantics, plus all-or-none
//! domain writes under the outer atomic runner's disposition.

use butter_workflow::jobs::{JobContinuationUpdate, JobFailureUpdate};
use butter_workflow::run_atomic;
use runledger_core::jobs::{JobFailureKind, JobStatus};

use super::{
    Failure,
    fixture::{Fixture, identity, write},
};

#[tokio::test]
async fn continuation_retains_checkpoint_and_domain_state_only_on_commit() {
    let fixture = Fixture::new("atomic_continuation").await;
    for commit in [true, false] {
        let job = fixture.claimed(30).await;
        let checkpoint = serde_json::json!({"page": 3});
        let update = JobContinuationUpdate {
            delay: std::time::Duration::from_secs(60),
            progress_done: Some(3),
            progress_total: Some(10),
            checkpoint: Some(&checkpoint),
        };
        let result = run_atomic(&fixture.profiled, async |scope| {
            let (_, outcome) = scope
                .queue()
                .complete_job_continuation(identity(&job), &update, async |sql| {
                    write(sql, job.id).await
                })
                .await
                .expect("compose continuation");
            assert_eq!(
                (outcome.completed_run_number, outcome.next_run_number),
                (1, 2)
            );
            if commit { Ok(()) } else { Err("rollback") }
        })
        .await;
        assert_eq!(result.is_ok(), commit);
        let row = fixture.job(job.id).await;
        assert_eq!(fixture.effects(job.id).await, i64::from(commit));
        assert_eq!(
            row.status,
            if commit {
                JobStatus::Pending
            } else {
                JobStatus::Leased
            }
        );
        assert_eq!(row.run_number, if commit { 2 } else { 1 });
        assert_eq!(row.checkpoint, if commit { Some(checkpoint) } else { None });
        assert_eq!(row.attempt, if commit { 0 } else { 1 });
    }
    fixture.close().await;
}

#[tokio::test]
async fn failure_preserves_retry_and_dead_letter_policy_with_atomic_domain_state() {
    let fixture = Fixture::new("atomic_failure").await;
    for (kind, commit) in [
        (JobFailureKind::Retryable, true),
        (JobFailureKind::Terminal, true),
        (JobFailureKind::Terminal, false),
    ] {
        let job = fixture.claimed(30).await;
        let update = JobFailureUpdate::new(kind, "test.failure", "synthetic failure", Some(60_000));
        let result = run_atomic(&fixture.profiled, async |scope| {
            scope
                .queue()
                .complete_job_failure(identity(&job), &update, async |sql| {
                    write(sql, job.id).await
                })
                .await
                .expect("compose failure");
            if commit { Ok(()) } else { Err("rollback") }
        })
        .await;
        assert_eq!(result.is_ok(), commit);
        assert_eq!(fixture.effects(job.id).await, i64::from(commit));
        let row = fixture.job(job.id).await;
        let expected = if !commit {
            JobStatus::Leased
        } else if kind == JobFailureKind::Retryable {
            JobStatus::Pending
        } else {
            JobStatus::DeadLettered
        };
        assert_eq!(row.status, expected);
        let dead: i64 = sqlx::query_scalar("SELECT count(*) FROM job_dead_letters WHERE job_id=$1")
            .bind(job.id)
            .fetch_one(&fixture.pool)
            .await
            .expect("read dead-letter evidence");
        assert_eq!(dead, i64::from(commit && kind == JobFailureKind::Terminal));
    }
    fixture.close().await;
}

#[tokio::test]
async fn caught_callback_rejection_discards_both_parts() {
    let fixture = Fixture::new("atomic_callback_rejected").await;
    let job = fixture.claimed(30).await;
    let result = run_atomic(&fixture.profiled, async |scope| {
        let rejected = scope
            .queue()
            .complete_job_success(identity(&job), None, async |sql| {
                write(sql, job.id).await?;
                Err::<(), Failure>(std::io::Error::other("domain rejection").into())
            })
            .await;
        assert!(rejected.is_err());
        Ok::<_, ()>(())
    })
    .await;
    assert!(
        result.is_ok(),
        "ordinary rejection was recovered after savepoint rollback"
    );
    assert_eq!(fixture.effects(job.id).await, 0);
    assert_eq!(fixture.job(job.id).await.status, JobStatus::Leased);
    fixture.close().await;
}

#[tokio::test]
async fn caught_native_storage_failure_discards_domain_and_partial_lifecycle_writes() {
    let fixture = Fixture::new("atomic_native_completion_rejected").await;
    sqlx::raw_sql("CREATE FUNCTION reject_success_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic lifecycle failure' USING ERRCODE='23514'; END $$; CREATE TRIGGER reject_success_event BEFORE INSERT ON job_events FOR EACH ROW WHEN (NEW.event_type='SUCCEEDED') EXECUTE FUNCTION reject_success_event();")
        .execute(&fixture.pool).await.expect("install native event-write fault");
    let job = fixture.claimed(30).await;
    let result = run_atomic(&fixture.profiled, async |scope| {
        let rejected = scope
            .queue()
            .complete_job_success(identity(&job), None, async |sql| write(sql, job.id).await)
            .await;
        assert!(rejected.is_err());
        Ok::<_, ()>(())
    })
    .await;
    assert!(
        result.is_ok(),
        "recoverable native failure rolls back its savepoint"
    );
    assert_eq!(fixture.effects(job.id).await, 0);
    assert_eq!(fixture.job(job.id).await.status, JobStatus::Leased);
    let finished: bool = sqlx::query_scalar("SELECT finished_at IS NOT NULL FROM job_attempts WHERE job_id=$1 AND run_number=$2 AND attempt=$3")
        .bind(job.id).bind(job.run_number).bind(job.attempt).fetch_one(&fixture.pool).await.expect("read attempt");
    assert!(
        !finished,
        "the native attempt update preceded the failed event write and must also roll back"
    );
    fixture.close().await;
}
