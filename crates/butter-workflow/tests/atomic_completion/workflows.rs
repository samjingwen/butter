//! Oracle: native dependency counters, step states and job lifecycle must share
//! the same disposition as the consumer's domain writes, including rollback.

use butter_workflow::{
    jobs::{
        JobContinuationUpdate, JobFailureUpdate, claim_jobs_for_types, enqueue_workflow_run,
        list_workflow_steps,
    },
    run_atomic,
};
use runledger_core::jobs::{
    JobFailureKind, JobType, StepKey, WorkflowRunEnqueueBuilder, WorkflowStepEnqueueBuilder,
    WorkflowStepStatus, WorkflowType,
};

use super::{
    fixture::{Fixture, JOB_TYPE, WORKER, identity, write},
    support,
};

#[derive(Clone, Copy)]
enum Completion {
    Success,
    Continue,
    Fail,
}

#[tokio::test]
async fn workflow_propagation_and_domain_writes_share_completion_disposition() {
    let fixture = Fixture::new("atomic_workflow_lifecycle").await;
    support::register_test_job_definition(&fixture.pool, "test.atomic.dependent").await;
    for mode in [Completion::Success, Completion::Continue, Completion::Fail] {
        for commit in [true, false] {
            exercise(&fixture, mode, commit).await;
        }
    }
    fixture.close().await;
}

async fn exercise(fixture: &Fixture, mode: Completion, commit: bool) {
    let payload = serde_json::json!({});
    let root =
        WorkflowStepEnqueueBuilder::new(StepKey::new("root"), JobType::new(JOB_TYPE), &payload)
            .allow_handler_continuation()
            .try_build()
            .expect("root step");
    let dependent = WorkflowStepEnqueueBuilder::new(
        StepKey::new("dependent"),
        JobType::new("test.atomic.dependent"),
        &payload,
    )
    .depends_on_success(&[StepKey::new("root")])
    .try_build()
    .expect("dependent step");
    let workflow =
        WorkflowRunEnqueueBuilder::new(WorkflowType::new("test.atomic.workflow"), &payload)
            .step(root)
            .step(dependent)
            .try_build()
            .expect("workflow");
    let run = enqueue_workflow_run(&fixture.pool, &workflow)
        .await
        .expect("enqueue workflow");
    let job = claim_jobs_for_types(&fixture.pool, WORKER, 30, 1, &[JobType::new(JOB_TYPE)])
        .await
        .expect("claim root")
        .pop()
        .expect("root claim");
    let result = run_atomic(&fixture.profiled, async |scope| {
        let mut queue = scope.queue();
        match mode {
            Completion::Success => {
                queue
                    .complete_job_success(identity(&job), None, async |sql| {
                        write(sql, job.id).await
                    })
                    .await
                    .expect("complete workflow job");
            }
            Completion::Continue => {
                let update = JobContinuationUpdate {
                    delay: std::time::Duration::from_secs(60),
                    progress_done: None,
                    progress_total: None,
                    checkpoint: None,
                };
                queue
                    .complete_job_continuation(identity(&job), &update, async |sql| {
                        write(sql, job.id).await
                    })
                    .await
                    .expect("continue workflow job");
            }
            Completion::Fail => {
                let update = JobFailureUpdate::new(
                    JobFailureKind::Terminal,
                    "test.terminal",
                    "synthetic terminal",
                    None,
                );
                queue
                    .complete_job_failure(identity(&job), &update, async |sql| {
                        write(sql, job.id).await
                    })
                    .await
                    .expect("fail workflow job");
            }
        }
        let before_commit = list_workflow_steps(&fixture.pool, None, run.id)
            .await
            .expect("independent step read");
        assert!(
            before_commit
                .iter()
                .any(|s| s.step_key.as_str() == "root" && s.status == WorkflowStepStatus::Running)
        );
        assert!(
            before_commit
                .iter()
                .any(|s| s.step_key.as_str() == "dependent"
                    && s.status == WorkflowStepStatus::Blocked)
        );
        if commit {
            Ok(())
        } else {
            Err("reject entire completion")
        }
    })
    .await;
    assert_eq!(result.is_ok(), commit);
    assert_eq!(fixture.effects(job.id).await, i64::from(commit));
    let rows = list_workflow_steps(&fixture.pool, None, run.id)
        .await
        .expect("committed steps");
    let root = rows
        .iter()
        .find(|s| s.step_key.as_str() == "root")
        .expect("root");
    let dependent = rows
        .iter()
        .find(|s| s.step_key.as_str() == "dependent")
        .expect("dependent");
    let expected = if !commit {
        (WorkflowStepStatus::Running, WorkflowStepStatus::Blocked, 1)
    } else {
        match mode {
            Completion::Success => (
                WorkflowStepStatus::Succeeded,
                WorkflowStepStatus::Enqueued,
                0,
            ),
            Completion::Continue => (WorkflowStepStatus::Enqueued, WorkflowStepStatus::Blocked, 1),
            Completion::Fail => (WorkflowStepStatus::Failed, WorkflowStepStatus::Canceled, 0),
        }
    };
    assert_eq!(
        (
            root.status,
            dependent.status,
            dependent.dependency_count_pending
        ),
        expected
    );
}
