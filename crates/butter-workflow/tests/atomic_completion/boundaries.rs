//! An abandoned inner operation and unsupported transaction control must retain
//! scope loss even when the consumer catches it and returns success.

use butter_workflow::{
    PgAtomicError, PgAtomicUncertainty, PgScopeError, PgScopeFailure, PgScopeLoss, run_atomic,
};
use runledger_core::jobs::JobStatus;
use std::time::Duration;

use super::{
    Failure,
    fixture::{Fixture, identity, write},
};

#[tokio::test]
async fn caught_inner_completion_cancellation_cannot_restore_commit_authority() {
    let fixture = Fixture::new("atomic_inner_completion_drop").await;
    let job = fixture.claimed(30).await;
    let result = run_atomic(&fixture.profiled, async |scope| {
        let mut queue = scope.queue();
        let (started, received) = tokio::sync::oneshot::channel();
        let mut completion =
            Box::pin(
                queue.complete_job_success(identity(&job), None, async |sql| {
                    write(sql, job.id).await?;
                    started.send(()).expect("signal completed domain write");
                    std::future::pending::<()>().await;
                    Ok::<_, Failure>(())
                }),
            );
        tokio::select! {
            result = &mut completion => panic!("callback must remain parked: {result:?}"),
            signal = received => signal.expect("callback entered"),
            () = tokio::time::sleep(Duration::from_secs(10)) => panic!("callback failed to start"),
        }
        drop(completion);
        let mut later_called = false;
        let later = queue
            .application(async |_sql| {
                later_called = true;
                Ok::<_, Failure>(())
            })
            .await;
        assert!(
            !later_called,
            "abandoned completion must not admit more application work"
        );
        assert!(matches!(
            later,
            Err(PgScopeError::Terminal(PgScopeFailure::OperationAbandoned))
        ));
        Ok::<_, ()>(())
    })
    .await;
    assert!(matches!(
        result,
        Err(PgAtomicError::Uncertain(PgAtomicUncertainty::ScopeLost {
            result: Ok(()),
            cause: PgScopeLoss::OperationAbandoned,
        }))
    ));
    tokio::time::timeout(
        Duration::from_secs(5),
        sqlx::query("SELECT id FROM job_queue WHERE id=$1 FOR UPDATE")
            .bind(job.id)
            .execute(&fixture.pool),
    )
    .await
    .expect("retired session releases job lock")
    .expect("observe job lock release");
    assert_eq!(fixture.effects(job.id).await, 0);
    assert_eq!(fixture.job(job.id).await.status, JobStatus::Leased);
    fixture.close().await;
}

#[tokio::test]
async fn caught_transaction_escape_remains_uncertain_not_rollback_proof() {
    let fixture = Fixture::new("atomic_completion_boundary_loss").await;
    for (control, effects) in [("COMMIT; BEGIN", 1), ("ROLLBACK; BEGIN", 0)] {
        let job = fixture.claimed(30).await;
        let result = run_atomic(&fixture.profiled, async |scope| {
            let failure = scope
                .queue()
                .complete_job_success(identity(&job), None, async |sql| {
                    write(sql, job.id).await?;
                    // Deliberately unsupported SQL. A missing savepoint must not be
                    // mistaken for acknowledged rollback of the original operation.
                    sqlx::raw_sql(sqlx::AssertSqlSafe(control))
                        .execute(sql.executor())
                        .await?;
                    Err::<(), Failure>(std::io::Error::other("reject after boundary loss").into())
                })
                .await;
            assert!(matches!(
                failure,
                Err(PgScopeError::Terminal(PgScopeFailure::Recovery { .. }))
            ));
            Ok::<_, ()>(())
        })
        .await;
        assert!(matches!(
            result,
            Err(PgAtomicError::Uncertain(PgAtomicUncertainty::ScopeLost {
                result: Ok(()),
                cause: PgScopeLoss::Transaction(_),
            }))
        ));
        assert_eq!(
            fixture.effects(job.id).await,
            effects,
            "scope loss cannot undo effects that unsupported SQL already committed"
        );
        assert_eq!(fixture.job(job.id).await.status, JobStatus::Leased);
    }
    fixture.close().await;
}
