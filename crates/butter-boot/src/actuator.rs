//! HTTP policy only; all operation semantics stay transport independent.
use butter_actuator::{HEALTH_OPERATIONS, HealthView, RunningActuator, Status};
use butter_core::BoxError;
use butter_web::{
    ProbePath, PublicReadSubtree,
    native::{
        http::{StatusCode, header},
        response::IntoResponse,
    },
};

pub(super) fn routes(view: RunningActuator) -> Result<PublicReadSubtree, BoxError> {
    let mut routes = PublicReadSubtree::new(ProbePath::new("/actuator")?)?;
    for operation in HEALTH_OPERATIONS {
        let path = match operation.view {
            HealthView::Overall => "/actuator/health",
            HealthView::Liveness => "/actuator/health/liveness",
            HealthView::Readiness => "/actuator/health/readiness",
        };
        let view = view.clone();
        routes = routes.read(ProbePath::new(path)?, move |_| {
            let (status, body) = match view.health(operation.view).status {
                Status::Up => (StatusCode::OK, r#"{"status":"UP"}"#),
                Status::Down => (StatusCode::SERVICE_UNAVAILABLE, r#"{"status":"DOWN"}"#),
            };
            // Only two fixed JSON literals exist, so serialization is infallible.
            (
                status,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                body,
            )
                .into_response()
        })?;
    }
    Ok(routes)
}

#[cfg(test)]
mod tests;
