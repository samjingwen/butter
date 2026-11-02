mod common;
mod continuation;
mod failure;
mod heartbeat;
mod progress;
mod success;

pub(crate) use continuation::complete_job_continuation_in_transaction;
pub(crate) use failure::complete_job_failure_in_transaction;
pub(crate) use success::complete_job_success_in_transaction;

pub(crate) async fn require_live_job_lease_in_transaction(
    tx: &mut impl crate::PgTransactionalExecutor,
    identity: crate::jobs::JobLeaseIdentity<'_>,
) -> crate::Result<()> {
    common::lock_live_job_lease_tx(tx, identity, "lock atomic completion authority")
        .await?
        .ok_or_else(crate::jobs::errors::lease_owner_mismatch_error)?;
    // A SELECT predicate can be evaluated before a row-lock wait. Check time
    // again on the locked row before handing application SQL to the callback.
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM job_queue WHERE id=$1 AND run_number=$2
         AND attempt=$3 AND worker_id=$4 AND status='LEASED'
         AND lease_expires_at > clock_timestamp())",
    )
    .bind(identity.job_id)
    .bind(identity.run_number)
    .bind(identity.attempt)
    .bind(identity.worker_id)
    .fetch_one(tx.executor())
    .await
    .map_err(|error| {
        crate::Error::from_query_sqlx_with_context("recheck locked completion authority", error)
    })?;
    if !live {
        return Err(crate::jobs::errors::lease_owner_mismatch_error());
    }
    Ok(())
}

pub use self::continuation::{
    complete_job_continuation, complete_job_continuation_for_lease,
    complete_job_continuation_with_outcome, complete_job_continuation_with_outcome_for_lease,
};
pub use self::failure::{
    complete_job_failure, complete_job_failure_for_lease, complete_job_failure_with_outcome,
    complete_job_failure_with_outcome_for_lease,
};
pub use self::heartbeat::{heartbeat_job, heartbeat_job_for_lease};
#[allow(
    deprecated,
    reason = "deprecated stage-bearing progress wrappers remain re-exported for semver compatibility"
)]
pub use self::progress::{
    mark_job_running, mark_job_running_for_lease, update_job_ordinary_progress,
    update_job_ordinary_progress_for_lease, update_job_progress, update_job_progress_for_lease,
};
pub use self::success::{
    complete_job_success, complete_job_success_for_lease, complete_job_success_with_outcome,
    complete_job_success_with_outcome_for_lease,
};
