//! Oracles: a lease must still be live when completion runs; repeated delivery
//! cannot execute a second domain write; interrupted work returns no commit proof.

use butter_workflow::{PgAtomicError, PgAtomicUncertainty, RunledgerDatabase, run_atomic};
use runledger_core::jobs::JobStatus;
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use super::{
    Failure,
    fixture::{Fixture, identity, write},
    support,
};

#[tokio::test]
async fn lease_expiring_behind_row_lock_never_invokes_domain_callback() {
    let fixture = Fixture::new("atomic_expiry_behind_lock").await;
    let job = fixture.claimed(3).await;
    let mut blocker = fixture.pool.begin().await.expect("begin blocker");
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .expect("blocker identity");
    sqlx::query("SELECT id FROM job_queue WHERE id=$1 FOR UPDATE")
        .bind(job.id)
        .execute(&mut *blocker)
        .await
        .expect("lock fixture row");
    let called = AtomicUsize::new(0);
    let mut completion = Box::pin(run_atomic(&fixture.profiled, async |scope| {
        scope
            .queue()
            .complete_job_success(identity(&job), None, async |_sql| {
                called.fetch_add(1, Ordering::SeqCst);
                Ok::<_, Failure>(())
            })
            .await
    }));
    let observe_waiter = async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))")
                .bind(blocker_pid).fetch_one(&fixture.pool).await.expect("observe blocked completion");
            if waiting {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::select! {
        result = &mut completion => panic!("completion must wait behind fixture lock: {result:?}"),
        result = tokio::time::timeout(Duration::from_secs(3), observe_waiter) => result.expect("observe actual lock wait"),
    }
    sqlx::query("SELECT pg_sleep(GREATEST(EXTRACT(EPOCH FROM lease_expires_at - clock_timestamp()), 0)::double precision + 0.025) FROM job_queue WHERE id=$1")
        .bind(job.id).execute(&mut *blocker).await.expect("let the actual database lease expire");
    blocker
        .rollback()
        .await
        .expect("release unchanged locked row");
    assert!(completion.await.is_err());
    assert_eq!(called.load(Ordering::SeqCst), 0);
    fixture.close().await;
}

#[tokio::test]
async fn expiry_during_domain_callback_rolls_back_its_writes() {
    let fixture = Fixture::new("atomic_expired_callback").await;
    let job = fixture.claimed(5).await;
    let called = AtomicUsize::new(0);
    let result = run_atomic(&fixture.profiled, async |scope| {
        scope.queue().complete_job_success(identity(&job), None, async |sql| {
            called.fetch_add(1, Ordering::SeqCst);
            write(sql, job.id).await?;
            // Fault timing is driven by the database's actual lease deadline,
            // not an assumed client sleep or an invented lease mutation.
            sqlx::query("SELECT pg_sleep(GREATEST(EXTRACT(EPOCH FROM lease_expires_at - clock_timestamp()), 0)::double precision + 0.025) FROM job_queue WHERE id=$1")
                .bind(job.id).execute(sql.executor()).await?;
            Ok::<_, Failure>(())
        }).await
    }).await;
    assert!(result.is_err());
    assert_eq!(called.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.effects(job.id).await, 0);
    assert_eq!(fixture.job(job.id).await.status, JobStatus::Leased);
    fixture.close().await;
}

#[tokio::test]
async fn independent_concurrent_completions_run_domain_work_once() {
    let fixture = Fixture::new("atomic_completion_race").await;
    let other = support::profiled_database(&fixture.pool).await;
    let job = fixture.claimed(30).await;
    let called = AtomicUsize::new(0);
    let operation = async |db: &RunledgerDatabase| {
        run_atomic(db, async |scope| {
            scope
                .queue()
                .complete_job_success(identity(&job), None, async |sql| {
                    called.fetch_add(1, Ordering::SeqCst);
                    write(sql, job.id).await
                })
                .await
        })
        .await
    };
    let (first, second) = tokio::join!(operation(&fixture.profiled), operation(&other));
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert_eq!(called.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.effects(job.id).await, 1);
    assert_eq!(fixture.job(job.id).await.status, JobStatus::Succeeded);
    other.pool().close().await;
    fixture.close().await;
}

#[tokio::test]
async fn commit_failure_retains_provisional_completion_as_uncertain() {
    let fixture = Fixture::new("atomic_completion_commit_failure").await;
    sqlx::raw_sql("CREATE FUNCTION reject_effect_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic deferred failure' USING ERRCODE='40001'; END $$; CREATE CONSTRAINT TRIGGER reject_effect_commit AFTER INSERT ON completion_effects DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_effect_commit();")
        .execute(&fixture.pool).await.expect("install commit-time fault");
    let job = fixture.claimed(30).await;
    let result = run_atomic(&fixture.profiled, async |scope| {
        scope
            .queue()
            .complete_job_success(identity(&job), None, async |sql| write(sql, job.id).await)
            .await
    })
    .await;
    let Err(PgAtomicError::Uncertain(PgAtomicUncertainty::CommitUnconfirmed {
        output: (_, outcome),
        ..
    })) = result
    else {
        panic!("unconfirmed commit must not become an ordinary rejected operation");
    };
    assert_eq!(outcome.job_id, job.id);
    assert_eq!(fixture.effects(job.id).await, 0);
    assert_eq!(fixture.job(job.id).await.status, JobStatus::Leased);
    fixture.close().await;
}

#[tokio::test]
async fn dropping_inflight_completion_releases_locks_without_committing_domain_work() {
    let fixture = Fixture::new("atomic_completion_drop").await;
    let job = fixture.claimed(30).await;
    let (started, received) = tokio::sync::oneshot::channel();
    let mut completion = Box::pin(run_atomic(&fixture.profiled, async |scope| {
        scope
            .queue()
            .complete_job_success(identity(&job), None, async |sql| {
                write(sql, job.id).await?;
                started.send(()).expect("signal callback entered");
                std::future::pending::<()>().await;
                Ok::<_, Failure>(())
            })
            .await
    }));
    tokio::select! {
        result = &mut completion => panic!("callback must remain parked: {result:?}"),
        signal = received => signal.expect("callback entered"),
        () = tokio::time::sleep(Duration::from_secs(10)) => panic!("callback failed to start"),
    }
    drop(completion);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match sqlx::query("SELECT id FROM job_queue WHERE id=$1 FOR UPDATE NOWAIT")
                .bind(job.id)
                .execute(&fixture.pool)
                .await
            {
                Ok(_) => break,
                Err(error)
                    if error.as_database_error().and_then(|e| e.code()).as_deref()
                        == Some("55P03") =>
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("unexpected lock observation failure: {error}"),
            }
        }
    })
    .await
    .expect("independently observe lock release after session retirement");
    assert_eq!(fixture.effects(job.id).await, 0);
    assert_eq!(fixture.job(job.id).await.status, JobStatus::Leased);
    fixture.close().await;
}

#[tokio::test]
async fn retry_after_discarded_completion_reply_does_not_repeat_domain_work() {
    let fixture = Fixture::new("atomic_completion_lost_reply").await;
    let job = fixture.claimed(30).await;
    let called = AtomicUsize::new(0);
    // The API committed but its caller did not retain the reply. Recovery must
    // inspect the durable outcome, not repeat the domain or provider operation.
    let _ = run_atomic(&fixture.profiled, async |scope| {
        scope
            .queue()
            .complete_job_success(identity(&job), None, async |sql| {
                called.fetch_add(1, Ordering::SeqCst);
                write(sql, job.id).await
            })
            .await
    })
    .await
    .expect("first completion committed");
    let repeated = run_atomic(&fixture.profiled, async |scope| {
        scope
            .queue()
            .complete_job_success(identity(&job), None, async |sql| {
                called.fetch_add(1, Ordering::SeqCst);
                write(sql, job.id).await
            })
            .await
    })
    .await;
    assert!(
        repeated.is_err(),
        "a finished lease is not fresh execution authority"
    );
    assert_eq!(called.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.effects(job.id).await,
        1,
        "the committed domain outcome remains discoverable"
    );
    fixture.close().await;
}
