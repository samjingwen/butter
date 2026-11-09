//! Application assembly from inert HTTP configuration to checked shutdown.
//!
//! Bootstrap reuses the upstream protected startup, HTTP boundary and independent
//! shutdown driver. It does not install a global tracing subscriber, provision a
//! database, or start an undeclared worker.

use butter_core::{
    BoxError,
    cleanup::CleanupBudget,
    lifecycle::{LifecycleStatus, RunningSupervisor, ShutdownBudget, ShutdownSuccess, Supervisor},
    operation::OperationOwner,
    startup::{ApplicationError, ProtectedStartupScope, Startup, StartupFuture},
};
use butter_web::{HttpBoundary, RequestPolicy, ResponseConstructionBudget, Router};
use std::{net::SocketAddr, time::Duration};

#[cfg(feature = "actuator")]
mod actuator;

type ApplicationInitializer = Box<
    dyn for<'a> FnOnce(&'a mut ProtectedStartupScope) -> StartupFuture<'a, ApplicationError> + Send,
>;

/// Inert HTTP application configuration. Construction performs no I/O.
///
/// No management routes are installed unless an Actuator is explicitly attached.
/// Conflicting routes fail assembly before a listener is bound. The default listener is
/// IPv4 loopback port 8080, never an automatically public interface.
///
/// ```no_run
/// use butter_boot::Application;
/// use butter_web::{Router, routing::get};
/// # async fn example() -> Result<(), butter_core::BoxError> {
/// let running = Application::new(Router::new().route("/", get(|| async { "hello" })))
///     .bind("127.0.0.1:0".parse()?)
///     .start().await?;
/// let _address = running.address();
/// let _completed = running.shutdown().await?;
/// # Ok(()) }
/// ```
#[must_use = "start or run the configured application"]
pub struct Application {
    routes: Router,
    address: SocketAddr,
    request_budget: ResponseConstructionBudget,
    initializers: Vec<ApplicationInitializer>,
    #[cfg(feature = "security-web")]
    security: Option<butter_security_web::SecurityWeb>,
    #[cfg(feature = "actuator")]
    actuator: Option<butter_actuator::Actuator>,
}

impl Application {
    /// Configure one protected HTTP service with a 30-second response-construction budget.
    /// Request-body streaming and arbitrary detached application tasks are not
    /// bounded by this response-construction deadline.
    pub fn new(routes: Router) -> Self {
        Self {
            routes,
            address: SocketAddr::from(([127, 0, 0, 1], 8080)),
            request_budget: ResponseConstructionBudget::new(Duration::from_secs(30))
                .expect("constant response-construction budget is valid"),
            initializers: Vec::new(),
            #[cfg(feature = "security-web")]
            security: None,
            #[cfg(feature = "actuator")]
            actuator: None,
        }
    }

    /// Select an explicit listener address. Port zero requests an OS-assigned port.
    pub fn bind(mut self, address: SocketAddr) -> Self {
        self.address = address;
        self
    }

    /// Explicitly attach operational health. Compilation alone installs no routes.
    /// Repeated attachment is rejected without replacing the first plan.
    #[cfg(feature = "actuator")]
    pub fn actuator(mut self, actuator: butter_actuator::Actuator) -> Result<Self, BoxError> {
        if self.actuator.is_some() {
            return Err(std::io::Error::other("Actuator already attached").into());
        }
        self.actuator = Some(actuator);
        Ok(self)
    }

    /// Select an already validated response-construction budget.
    pub fn request_budget(mut self, budget: ResponseConstructionBudget) -> Self {
        self.request_budget = budget;
        self
    }

    /// Explicitly attach validated web security to all application routes.
    ///
    /// Attachment is inert until startup. Butter applies the security layer
    /// after route construction and immediately before HTTP assembly, so routes
    /// cannot accidentally be appended outside the canonical security boundary.
    /// Separately attached Actuator reads remain outside application security.
    /// Repeated attachment is rejected without replacing the first plan.
    #[cfg(feature = "security-web")]
    pub fn security(
        mut self,
        security: butter_security_web::SecurityWeb,
    ) -> Result<Self, BoxError> {
        if self.security.is_some() {
            return Err(std::io::Error::other("web security already attached").into());
        }
        self.security = Some(security);
        Ok(self)
    }

    /// Add protected application initialization before HTTP assembly and binding.
    ///
    /// Initializers run in declaration order and may await native acquisition or
    /// validation. Reserve cleanup before acquisition with
    /// [`ProtectedStartupScope::reserve_cleanup`], then register it immediately
    /// after success. Registered cleanup participates in failed-startup rollback
    /// and checked shutdown under the application's bounded LIFO cleanup policy.
    ///
    /// ```no_run
    /// use butter_boot::Application;
    /// use butter_web::Router;
    /// # async fn example() -> Result<(), butter_core::BoxError> {
    /// let application = Application::new(Router::new()).initialize(|scope| {
    ///     Box::pin(async move {
    ///         let slot = scope.reserve_cleanup("store.pool")?;
    ///         let resource = String::from("acquired");
    ///         slot.register(move || async move {
    ///             drop(resource);
    ///             Ok(())
    ///         });
    ///         Ok(())
    ///     })
    /// });
    /// application.bind("127.0.0.1:0".parse()?).start().await?.shutdown().await?;
    /// # Ok(()) }
    /// ```
    pub fn initialize<F>(mut self, initialize: F) -> Self
    where
        F: for<'a> FnOnce(&'a mut ProtectedStartupScope) -> StartupFuture<'a, ApplicationError>
            + Send
            + 'static,
    {
        self.initializers.push(Box::new(initialize));
        self
    }

    /// Bind and start, returning only after native component readiness.
    /// Does not install process signal listeners; suitable for embedded applications and tests.
    pub async fn start(self) -> Result<RunningApplication, BoxError> {
        self.start_inner(false).await
    }

    /// Start with process-owned SIGINT/SIGTERM handling, returning after readiness.
    /// Use [`Self::start`] when the embedding application already owns signals.
    #[cfg(unix)]
    pub async fn start_with_signals(self) -> Result<RunningApplication, BoxError> {
        self.start_inner(true).await
    }

    /// Start with SIGINT/SIGTERM handling and await checked process completion.
    /// The application root owns its Tokio runtime and logging installation.
    #[cfg(unix)]
    pub async fn run(self) -> Result<ShutdownSuccess, BoxError> {
        self.start_with_signals().await?.wait().await
    }

    async fn start_inner(self, signals: bool) -> Result<RunningApplication, BoxError> {
        let Application {
            routes,
            address,
            request_budget,
            initializers,
            #[cfg(feature = "security-web")]
            security,
            #[cfg(feature = "actuator")]
            actuator,
        } = self;
        let second = Duration::from_secs(1);
        let cleanup = CleanupBudget::new(second * 5, second * 3, second)?;
        let supervisor = Supervisor::new(ShutdownBudget::new(
            second * 10,
            second * 2,
            second,
            cleanup,
        )?);
        #[cfg(feature = "actuator")]
        let lifecycle = supervisor.status();
        let admission = supervisor.operation_admission();
        let startup = Startup::protected(
            supervisor,
            OperationOwner::new(second * 15)?.into_context(),
            cleanup,
            async move |scope| {
                for initialize in initializers {
                    initialize(scope).await?;
                }
                scope.stage("http.assemble")?;
                #[cfg(feature = "security-web")]
                let routes = match security {
                    Some(security) => security.protect(routes),
                    None => routes,
                };
                let policy = RequestPolicy::new(admission, request_budget);
                #[cfg(feature = "actuator")]
                let public = actuator
                    .map(|plan| plan.register_in(scope, lifecycle))
                    .transpose()?;
                #[cfg(feature = "actuator")]
                if let Some(view) = public {
                    let http = actuator::routes(view)?.assemble(policy, routes).await?;
                    scope.stage("http.bind")?;
                    let listener = tokio::net::TcpListener::bind(address).await?;
                    let address = listener.local_addr()?;
                    http.register_in(scope, "http", listener)?;
                    return Ok::<_, ApplicationError>(address);
                }
                let http = HttpBoundary::new(policy).assemble(routes).await?;
                scope.stage("http.bind")?;
                let listener = tokio::net::TcpListener::bind(address).await?;
                let address = listener.local_addr()?;
                http.register_in(scope, "http", listener)?;
                Ok::<_, ApplicationError>(address)
            },
        );
        let startup = if signals {
            startup.with_unix_signals("signals")
        } else {
            startup
        };
        let mut starting = startup.start();
        let (driver, address) = starting.wait_with_output().await?;
        if driver.status().wait_ready().await.is_err() {
            // Always retain checked completion rather than turning an early
            // component failure into an invented successful startup.
            driver.shutdown_checked().await?;
            return Err(std::io::Error::other("application stopped before readiness").into());
        }
        Ok(RunningApplication { driver, address })
    }
}

/// An initialized application backed by an independently owned lifecycle driver.
/// Dropping this value requests drain; it is not proof of completed shutdown.
/// Borrowed waiter cancellation leaves the owner and cleanup driver intact.
#[must_use = "await shutdown or process completion"]
pub struct RunningApplication {
    driver: RunningSupervisor,
    address: SocketAddr,
}

impl RunningApplication {
    /// The actual bound address, including an OS-assigned port.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Read-only readiness and lifecycle observation.
    pub fn status(&self) -> LifecycleStatus {
        self.driver.status()
    }

    /// Observe retained completion without retaining shutdown ownership.
    pub fn observer(&self) -> butter_core::lifecycle::SupervisorObserver {
        self.driver.observer()
    }

    /// Wait without initiating shutdown. Cancelling this borrow does not drain the application.
    pub async fn wait(&self) -> Result<ShutdownSuccess, BoxError> {
        Ok(self.driver.wait_checked().await?)
    }

    /// Consume the owner, request shutdown and await checked completion.
    /// If this waiter is cancelled, the native coordinator still owns settlement
    /// while the Tokio runtime remains alive. No runtime-death guarantee is implied.
    pub async fn shutdown(self) -> Result<ShutdownSuccess, BoxError> {
        Ok(self.driver.shutdown_checked().await?)
    }
}
