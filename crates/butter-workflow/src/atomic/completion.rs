use super::{PgQueueScope, PgScopeError, PgScopedSql};
use crate::{
    Error,
    jobs::{
        JobCompletionUpdate, JobContinuationOutcome, JobContinuationUpdate,
        JobFailureCompletionOutcome, JobFailureUpdate, JobLeaseIdentity,
        JobSuccessCompletionOutcome,
    },
};

pub(super) async fn complete_with<T, O, E>(
    sql: &mut PgScopedSql<'_>,
    identity: JobLeaseIdentity<'_>,
    work: impl AsyncFnOnce(&mut PgScopedSql<'_>) -> Result<T, E>,
    completion: impl AsyncFnOnce(&mut PgScopedSql<'_>) -> crate::Result<O>,
) -> Result<(T, O), E>
where
    E: From<Error>,
{
    crate::jobs::require_live_job_lease_in_transaction(sql, identity)
        .await
        .map_err(E::from)?;
    let result = work(sql).await?;
    let outcome = completion(sql).await.map_err(E::from)?;
    Ok((result, outcome))
}

impl PgQueueScope<'_> {
    /// Persist application SQL and exact-live-lease success as one atomic operation.
    ///
    /// The library locks and checks the lease before invoking `work`, then applies
    /// native completion in the same protected savepoint. An expired lease,
    /// application rejection or lifecycle failure rolls back both parts, including
    /// when the caller catches the returned error. Scope loss remains retained by
    /// the owning atomic runner and cannot become a successful commit by catching it.
    /// Both outputs remain provisional until that runner acknowledges commit.
    ///
    /// `work` owns domain generation, cancellation and authorization checks. It must
    /// contain database work only, use a consistent application lock order, and not
    /// manipulate Runledger tables or perform transaction control. Remote effects
    /// are not part of this transaction and are never replayed by this method.
    /// Unsupported transaction-control SQL can commit effects before scope loss
    /// is detected; uncertainty is not a promise those effects were rolled back.
    ///
    /// ```no_run
    /// # async fn example(db: &butter_workflow::RunledgerDatabase, lease: butter_workflow::jobs::JobLeaseIdentity<'_>) {
    /// type Failure = Box<dyn std::error::Error + Send + Sync>;
    /// let committed = butter_workflow::run_atomic(db, async |scope| {
    ///     scope.queue().complete_job_success(lease, None, async |sql| {
    ///         sqlx::query("INSERT INTO result_audit (job_id) VALUES ($1)")
    ///             .bind(lease.job_id).execute(sql.executor()).await?;
    ///         Ok::<_, Failure>(())
    ///     }).await
    /// }).await;
    /// # let _ = committed;
    /// # }
    /// ```
    /// A separate, forgotten application/finalize pair is not required: domain
    /// work is a mandatory argument of the completion operation.
    /// ```compile_fail,E0061
    /// # async fn invalid(db: &butter_workflow::RunledgerDatabase, lease: butter_workflow::jobs::JobLeaseIdentity<'_>) {
    /// butter_workflow::run_atomic(db, async |scope| {
    ///     scope.queue().complete_job_success(lease, None).await
    /// }).await;
    /// # }
    /// ```
    /// Named completion cannot precede the consuming queue-phase transition.
    /// ```compile_fail,E0599
    /// # async fn invalid(db: &butter_workflow::RunledgerDatabase, lease: butter_workflow::jobs::JobLeaseIdentity<'_>) {
    /// butter_workflow::run_atomic(db, async |mut scope| {
    ///     scope.complete_job_success(lease, None, async |_sql| Ok::<_, butter_workflow::Error>(())).await
    /// }).await;
    /// # }
    /// ```
    pub async fn complete_job_success<T, E>(
        &mut self,
        identity: JobLeaseIdentity<'_>,
        progress: Option<&JobCompletionUpdate<'_>>,
        work: impl AsyncFnOnce(&mut PgScopedSql<'_>) -> Result<T, E>,
    ) -> Result<(T, JobSuccessCompletionOutcome), PgScopeError<E>>
    where
        E: From<Error>,
    {
        self.inner
            .application(async |sql| {
                complete_with(sql, identity, work, async |sql| {
                    crate::jobs::complete_job_success_in_transaction(sql, identity, progress).await
                })
                .await
            })
            .await
    }

    /// Persist application SQL and a native continuation in one protected operation.
    ///
    /// Has the authority, savepoint, provisional-output and domain-policy contract
    /// of [`Self::complete_job_success`]. Native continuation retains progress and
    /// checkpoints, advances the run, and enforces workflow continuation opt-in.
    /// A refusal or expiry after `work` rolls back its writes as well as the
    /// continuation. The callback must not perform external effects.
    ///
    /// ```no_run
    /// # async fn example(db: &butter_workflow::RunledgerDatabase, lease: butter_workflow::jobs::JobLeaseIdentity<'_>, update: &butter_workflow::jobs::JobContinuationUpdate<'_>) {
    /// let committed = butter_workflow::run_atomic(db, async |scope| {
    ///     scope.queue().complete_job_continuation(lease, update, async |sql| {
    ///         sqlx::query("INSERT INTO result_audit (job_id) VALUES ($1)")
    ///             .bind(lease.job_id).execute(sql.executor()).await?;
    ///         Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    ///     }).await
    /// }).await;
    /// # let _ = committed;
    /// # }
    /// ```
    pub async fn complete_job_continuation<T, E>(
        &mut self,
        identity: JobLeaseIdentity<'_>,
        continuation: &JobContinuationUpdate<'_>,
        work: impl AsyncFnOnce(&mut PgScopedSql<'_>) -> Result<T, E>,
    ) -> Result<(T, JobContinuationOutcome), PgScopeError<E>>
    where
        E: From<Error>,
    {
        self.inner
            .application(async |sql| {
                complete_with(sql, identity, work, async |sql| {
                    crate::jobs::complete_job_continuation_in_transaction(
                        sql,
                        identity,
                        continuation,
                    )
                    .await
                })
                .await
            })
            .await
    }

    /// Persist application SQL with native retry or dead-letter completion.
    ///
    /// Has the atomicity and authority contract of [`Self::complete_job_success`].
    /// The native failure policy still owns retry timing, attempts, dead-letter
    /// evidence and workflow propagation. This method neither retries `work` nor
    /// converts external uncertainty into a replay-safe failure. A native failure
    /// outcome is a successful database operation; callback rejection is not.
    ///
    /// ```no_run
    /// # async fn example(db: &butter_workflow::RunledgerDatabase, lease: butter_workflow::jobs::JobLeaseIdentity<'_>, failure: &butter_workflow::jobs::JobFailureUpdate<'_>) {
    /// let committed = butter_workflow::run_atomic(db, async |scope| {
    ///     scope.queue().complete_job_failure(lease, failure, async |sql| {
    ///         sqlx::query("INSERT INTO failure_audit (job_id) VALUES ($1)")
    ///             .bind(lease.job_id).execute(sql.executor()).await?;
    ///         Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    ///     }).await
    /// }).await;
    /// # let _ = committed;
    /// # }
    /// ```
    pub async fn complete_job_failure<T, E>(
        &mut self,
        identity: JobLeaseIdentity<'_>,
        failure: &JobFailureUpdate<'_>,
        work: impl AsyncFnOnce(&mut PgScopedSql<'_>) -> Result<T, E>,
    ) -> Result<(T, JobFailureCompletionOutcome), PgScopeError<E>>
    where
        E: From<Error>,
    {
        self.inner
            .application(async |sql| {
                complete_with(sql, identity, work, async |sql| {
                    crate::jobs::complete_job_failure_in_transaction(sql, identity, failure).await
                })
                .await
            })
            .await
    }
}
