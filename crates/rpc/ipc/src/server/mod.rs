//! JSON-RPC IPC server implementation

use crate::server::{
    connection::{Incoming, IpcConn, JsonRpcStream},
    future::{ConnectionGuard, FutureDriver, StopHandle},
};
use futures::{FutureExt, Stream, StreamExt};
use jsonrpsee::{
    core::TEN_MB_SIZE_BYTES,
    server::{
        middleware::rpc::{either::Either, RpcLoggerLayer, RpcServiceT},
        AlreadyStoppedError, IdProvider, RandomIntegerIdProvider,
    },
    BoundedSubscriptions, MethodSink, Methods,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{oneshot, watch, OwnedSemaphorePermit},
};
use tower::{layer::util::Identity, Layer, Service};
use tracing::{debug, trace, warn};

// re-export so can be used during builder setup
use crate::server::{
    connection::IpcConnDriver,
    rpc_service::{RpcService, RpcServiceCfg},
};
pub use parity_tokio_ipc::Endpoint;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tower::layer::{util::Stack, LayerFn};

mod connection;
mod future;
mod ipc;
mod rpc_service;

/// Ipc Server implementation

// This is an adapted `jsonrpsee` Server, but for `Ipc` connections.
pub struct IpcServer<HttpMiddleware = Identity, RpcMiddleware = Identity> {
    /// The endpoint we listen for incoming transactions
    endpoint: Endpoint,
    id_provider: Arc<dyn IdProvider>,
    cfg: Settings,
    rpc_middleware: RpcServiceBuilder<RpcMiddleware>,
    http_middleware: tower::ServiceBuilder<HttpMiddleware>,
}

impl<HttpMiddleware, RpcMiddleware> IpcServer<HttpMiddleware, RpcMiddleware> {
    /// Returns the configured [Endpoint]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}

impl<HttpMiddleware, RpcMiddleware> IpcServer<HttpMiddleware, RpcMiddleware>
where
    RpcMiddleware: Layer<RpcService> + Clone + Send + 'static,
    for<'a> <RpcMiddleware as Layer<RpcService>>::Service: RpcServiceT<'a>,
    HttpMiddleware: Layer<TowerServiceNoHttp<RpcMiddleware>> + Send + 'static,
    <HttpMiddleware as Layer<TowerServiceNoHttp<RpcMiddleware>>>::Service: Send
        + Service<
            String,
            Response = Option<String>,
            Error = Box<dyn std::error::Error + Send + Sync + 'static>,
        >,
    <<HttpMiddleware as Layer<TowerServiceNoHttp<RpcMiddleware>>>::Service as Service<String>>::Future:
    Send + Unpin,
{
    /// Start responding to connections requests.
    ///
    /// This will run on the tokio runtime until the server is stopped or the ServerHandle is
    /// dropped.
    ///
    /// ```
    /// use jsonrpsee::RpcModule;
    /// use reth_ipc::server::Builder;
    /// async fn run_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    ///     let server = Builder::default().build("/tmp/my-uds");
    ///     let mut module = RpcModule::new(());
    ///     module.register_method("say_hello", |_, _| "lo")?;
    ///     let handle = server.start(module).await?;
    ///
    ///     // In this example we don't care about doing shutdown so let's it run forever.
    ///     // You may use the `ServerHandle` to shut it down or manage it yourself.
    ///     let server = tokio::spawn(handle.stopped());
    ///     server.await.unwrap();
    ///     Ok(())
    /// }
    /// ```
    pub async fn start(
        mut self,
        methods: impl Into<Methods>,
    ) -> Result<ServerHandle, IpcServerStartError> {
        let methods = methods.into();
        let (stop_tx, stop_rx) = watch::channel(());

        let stop_handle = StopHandle::new(stop_rx);

        // use a signal channel to wait until we're ready to accept connections
        let (tx, rx) = oneshot::channel();

        match self.cfg.tokio_runtime.take() {
            Some(rt) => rt.spawn(self.start_inner(methods, stop_handle, tx)),
            None => tokio::spawn(self.start_inner(methods, stop_handle, tx)),
        };
        rx.await.expect("channel is open")?;

        Ok(ServerHandle::new(stop_tx))
    }

    async fn start_inner(
        self,
        methods: Methods,
        stop_handle: StopHandle,
        on_ready: oneshot::Sender<Result<(), IpcServerStartError>>,
    ) {
        trace!(endpoint = ?self.endpoint.path(), "starting ipc server");

        if cfg!(unix) {
            // ensure the file does not exist
            if std::fs::remove_file(self.endpoint.path()).is_ok() {
                debug!(endpoint = ?self.endpoint.path(), "removed existing IPC endpoint file");
            }
        }

        let message_buffer_capacity = self.cfg.message_buffer_capacity;
        let max_request_body_size = self.cfg.max_request_body_size;
        let max_response_body_size = self.cfg.max_response_body_size;
        let max_log_length = self.cfg.max_log_length;
        let id_provider = self.id_provider;
        let max_subscriptions_per_connection = self.cfg.max_subscriptions_per_connection;

        let mut id: u32 = 0;
        let connection_guard = ConnectionGuard::new(self.cfg.max_connections as usize);

        let mut connections = FutureDriver::default();
        let endpoint_path = self.endpoint.path().to_string();
        let incoming = match self.endpoint.incoming() {
            Ok(connections) => {
                #[cfg(windows)]
                    let connections = Box::pin(connections);
                Incoming::new(connections)
            }
            Err(err) => {
                on_ready
                    .send(Err(IpcServerStartError { endpoint: endpoint_path, source: err }))
                    .ok();
                return
            }
        };
        // signal that we're ready to accept connections
        on_ready.send(Ok(())).ok();

        let mut incoming = Monitored::new(incoming, &stop_handle);

        trace!("accepting ipc connections");
        loop {
            match connections.select_with(&mut incoming).await {
                Ok(ipc) => {
                    trace!("established new connection");
                    let conn = match connection_guard.try_acquire() {
                        Some(conn) => conn,
                        None => {
                            warn!("Too many IPC connections. Please try again later.");
                            connections.add(ipc.reject_connection().boxed());
                            continue
                        }
                    };

                    let (tx, rx) = mpsc::channel::<String>(message_buffer_capacity as usize);
                    let method_sink = MethodSink::new_with_limit(tx, max_response_body_size);
                    let tower_service = TowerServiceNoHttp {
                        inner: ServiceData {
                            methods: methods.clone(),
                            max_request_body_size,
                            max_response_body_size,
                            max_log_length,
                            id_provider: id_provider.clone(),
                            stop_handle: stop_handle.clone(),
                            max_subscriptions_per_connection,
                            conn_id: id,
                            conn: Arc::new(conn),
                            bounded_subscriptions: BoundedSubscriptions::new(
                                max_subscriptions_per_connection,
                            ),
                            method_sink,
                        },
                        rpc_middleware: self.rpc_middleware.clone(),
                    };

                    let service = self.http_middleware.service(tower_service);
                    connections.add(Box::pin(spawn_connection(
                        ipc,
                        service,
                        stop_handle.clone(),
                        rx,
                    )));

                    id = id.wrapping_add(1);
                }
                Err(MonitoredError::Selector(err)) => {
                    tracing::error!("Error while awaiting a new IPC connection: {:?}", err);
                }
                Err(MonitoredError::Shutdown) => break,
            }
        }

        connections.await;
    }
}

impl std::fmt::Debug for IpcServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpcServer")
            .field("endpoint", &self.endpoint.path())
            .field("cfg", &self.cfg)
            .field("id_provider", &self.id_provider)
            .finish()
    }
}

/// Error thrown when server couldn't be started.
#[derive(Debug, thiserror::Error)]
#[error("failed to listen on ipc endpoint `{endpoint}`: {source}")]
pub struct IpcServerStartError {
    endpoint: String,
    #[source]
    source: io::Error,
}

/// Data required by the server to handle requests received via an IPC connection
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct ServiceData {
    /// Registered server methods.
    pub(crate) methods: Methods,
    /// Max request body size.
    pub(crate) max_request_body_size: u32,
    /// Max request body size.
    pub(crate) max_response_body_size: u32,
    /// Max length for logging for request and response
    ///
    /// Logs bigger than this limit will be truncated.
    pub(crate) max_log_length: u32,
    /// Subscription ID provider.
    pub(crate) id_provider: Arc<dyn IdProvider>,
    /// Stop handle.
    pub(crate) stop_handle: StopHandle,
    /// Max subscriptions per connection.
    pub(crate) max_subscriptions_per_connection: u32,
    /// Connection ID
    pub(crate) conn_id: u32,
    /// Handle to hold a `connection permit`.
    pub(crate) conn: Arc<OwnedSemaphorePermit>,
    /// Limits the number of subscriptions for this connection
    pub(crate) bounded_subscriptions: BoundedSubscriptions,
    /// Sink that is used to send back responses to the connection.
    ///
    /// This is used for subscriptions.
    pub(crate) method_sink: MethodSink,
}

/// Similar to [`tower::ServiceBuilder`] but doesn't
/// support any tower middleware implementations.
#[derive(Debug, Clone)]
pub struct RpcServiceBuilder<L>(tower::ServiceBuilder<L>);

impl Default for RpcServiceBuilder<Identity> {
    fn default() -> Self {
        RpcServiceBuilder(tower::ServiceBuilder::new())
    }
}

impl RpcServiceBuilder<Identity> {
    /// Create a new [`RpcServiceBuilder`].
    pub fn new() -> Self {
        Self(tower::ServiceBuilder::new())
    }
}

impl<L> RpcServiceBuilder<L> {
    /// Optionally add a new layer `T` to the [`RpcServiceBuilder`].
    ///
    /// See the documentation for [`tower::ServiceBuilder::option_layer`] for more details.
    pub fn option_layer<T>(
        self,
        layer: Option<T>,
    ) -> RpcServiceBuilder<Stack<Either<T, Identity>, L>> {
        let layer = if let Some(layer) = layer {
            Either::Left(layer)
        } else {
            Either::Right(Identity::new())
        };
        self.layer(layer)
    }

    /// Add a new layer `T` to the [`RpcServiceBuilder`].
    ///
    /// See the documentation for [`tower::ServiceBuilder::layer`] for more details.
    pub fn layer<T>(self, layer: T) -> RpcServiceBuilder<Stack<T, L>> {
        RpcServiceBuilder(self.0.layer(layer))
    }

    /// Add a [`tower::Layer`] built from a function that accepts a service and returns another
    /// service.
    ///
    /// See the documentation for [`tower::ServiceBuilder::layer_fn`] for more details.
    pub fn layer_fn<F>(self, f: F) -> RpcServiceBuilder<Stack<LayerFn<F>, L>> {
        RpcServiceBuilder(self.0.layer_fn(f))
    }

    /// Add a logging layer to [`RpcServiceBuilder`]
    ///
    /// This logs each request and response for every call.
    pub fn rpc_logger(self, max_log_len: u32) -> RpcServiceBuilder<Stack<RpcLoggerLayer, L>> {
        RpcServiceBuilder(self.0.layer(RpcLoggerLayer::new(max_log_len)))
    }

    /// Wrap the service `S` with the middleware.
    pub(crate) fn service<S>(&self, service: S) -> L::Service
    where
        L: tower::Layer<S>,
    {
        self.0.service(service)
    }
}

/// JsonRPSee service compatible with `tower`.
///
/// # Note
/// This is similar to [`hyper::service::service_fn`](https://docs.rs/hyper/latest/hyper/service/fn.service_fn.html).
#[derive(Debug, Clone)]
pub struct TowerServiceNoHttp<L> {
    inner: ServiceData,
    rpc_middleware: RpcServiceBuilder<L>,
}

impl<RpcMiddleware> Service<String> for TowerServiceNoHttp<RpcMiddleware>
where
    RpcMiddleware: for<'a> Layer<RpcService>,
    <RpcMiddleware as Layer<RpcService>>::Service: Send + Sync + 'static,
    for<'a> <RpcMiddleware as Layer<RpcService>>::Service: RpcServiceT<'a>,
{
    /// The response of a handled RPC call
    ///
    /// This is an `Option` because subscriptions and call responses are handled differently.
    /// This will be `Some` for calls, and `None` for subscriptions, because the subscription
    /// response will be emitted via the `method_sink`.
    type Response = Option<String>;

    type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    /// Opens door for back pressure implementation.
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: String) -> Self::Future {
        trace!("{:?}", request);

        let cfg = RpcServiceCfg::CallsAndSubscriptions {
            bounded_subscriptions: BoundedSubscriptions::new(
                self.inner.max_subscriptions_per_connection,
            ),
            id_provider: self.inner.id_provider.clone(),
            sink: self.inner.method_sink.clone(),
        };

        let max_response_body_size = self.inner.max_response_body_size as usize;
        let rpc_service = self.rpc_middleware.service(RpcService::new(
            self.inner.methods.clone(),
            max_response_body_size,
            self.inner.conn_id as usize,
            cfg,
        ));
        let conn = self.inner.conn.clone();
        // an ipc connection needs to handle read+write concurrently
        // even if the underlying rpc handler spawns the actual work or is does a lot of async any
        // additional overhead performed by `handle_request` can result in I/O latencies, for
        // example tracing calls are relatively CPU expensive on serde::serialize alone, moving this
        // work to a separate task takes the pressure off the connection so all concurrent responses
        // are also serialized concurrently and the connection can focus on read+write
        let f = tokio::task::spawn(async move {
            ipc::call_with_service(request, rpc_service, max_response_body_size, conn).await
        });

        Box::pin(async move { f.await.map_err(|err| err.into()) })
    }
}

/// Spawns the IPC connection onto a new task
async fn spawn_connection<S, T>(
    conn: IpcConn<JsonRpcStream<T>>,
    service: S,
    mut stop_handle: StopHandle,
    rx: mpsc::Receiver<String>,
) where
    S: Service<String, Response = Option<String>> + Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    S::Future: Send + Unpin,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let task = tokio::task::spawn(async move {
        let rx_item = ReceiverStream::new(rx);
        let conn = IpcConnDriver {
            conn,
            service,
            pending_calls: Default::default(),
            items: Default::default(),
        };
        tokio::pin!(conn, rx_item);

        loop {
            tokio::select! {
                _ = &mut conn => {
                   break
                }
                item = rx_item.next() => {
                    if let Some(item) = item {
                        conn.push_back(item);
                    }
                }
                _ = stop_handle.shutdown() => {
                    // shutdown
                    break
                }
            }
        }
    });

    task.await.ok();
}

/// This is a glorified select listening for new messages, while also checking the `stop_receiver`
/// signal.
struct Monitored<'a, F> {
    future: F,
    stop_monitor: &'a StopHandle,
}

impl<'a, F> Monitored<'a, F> {
    fn new(future: F, stop_monitor: &'a StopHandle) -> Self {
        Monitored { future, stop_monitor }
    }
}

enum MonitoredError<E> {
    Shutdown,
    Selector(E),
}

impl<'a, T, Item> Future for Monitored<'a, Incoming<T, Item>>
where
    T: Stream<Item = io::Result<Item>> + Unpin + 'static,
    Item: AsyncRead + AsyncWrite,
{
    type Output = Result<IpcConn<JsonRpcStream<Item>>, MonitoredError<io::Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.stop_monitor.shutdown_requested() {
            return Poll::Ready(Err(MonitoredError::Shutdown))
        }

        this.future.poll_accept(cx).map_err(MonitoredError::Selector)
    }
}

/// JSON-RPC IPC server settings.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Maximum size in bytes of a request.
    max_request_body_size: u32,
    /// Maximum size in bytes of a response.
    max_response_body_size: u32,
    /// Max length for logging for requests and responses
    ///
    /// Logs bigger than this limit will be truncated.
    max_log_length: u32,
    /// Maximum number of incoming connections allowed.
    max_connections: u32,
    /// Maximum number of subscriptions per connection.
    max_subscriptions_per_connection: u32,
    /// Number of messages that server is allowed `buffer` until backpressure kicks in.
    message_buffer_capacity: u32,
    /// Custom tokio runtime to run the server on.
    tokio_runtime: Option<tokio::runtime::Handle>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_request_body_size: TEN_MB_SIZE_BYTES,
            max_response_body_size: TEN_MB_SIZE_BYTES,
            max_log_length: 4096,
            max_connections: 100,
            max_subscriptions_per_connection: 1024,
            message_buffer_capacity: 1024,
            tokio_runtime: None,
        }
    }
}

/// Builder to configure and create a JSON-RPC server
#[derive(Debug)]
pub struct Builder<HttpMiddleware, RpcMiddleware> {
    settings: Settings,
    /// Subscription ID provider.
    id_provider: Arc<dyn IdProvider>,
    rpc_middleware: RpcServiceBuilder<RpcMiddleware>,
    http_middleware: tower::ServiceBuilder<HttpMiddleware>,
}

impl Default for Builder<Identity, Identity> {
    fn default() -> Self {
        Builder {
            settings: Settings::default(),
            id_provider: Arc::new(RandomIntegerIdProvider),
            rpc_middleware: RpcServiceBuilder::new(),
            http_middleware: tower::ServiceBuilder::new(),
        }
    }
}

impl<HttpMiddleware, RpcMiddleware> Builder<HttpMiddleware, RpcMiddleware> {
    /// Set the maximum size of a request body in bytes. Default is 10 MiB.
    pub fn max_request_body_size(mut self, size: u32) -> Self {
        self.settings.max_request_body_size = size;
        self
    }

    /// Set the maximum size of a response body in bytes. Default is 10 MiB.
    pub fn max_response_body_size(mut self, size: u32) -> Self {
        self.settings.max_response_body_size = size;
        self
    }

    /// Set the maximum size of a log
    pub fn max_log_length(mut self, size: u32) -> Self {
        self.settings.max_log_length = size;
        self
    }

    /// Set the maximum number of connections allowed. Default is 100.
    pub fn max_connections(mut self, max: u32) -> Self {
        self.settings.max_connections = max;
        self
    }

    /// Set the maximum number of connections allowed. Default is 1024.
    pub fn max_subscriptions_per_connection(mut self, max: u32) -> Self {
        self.settings.max_subscriptions_per_connection = max;
        self
    }

    /// The server enforces backpressure which means that
    /// `n` messages can be buffered and if the client
    /// can't keep with up the server.
    ///
    /// This `capacity` is applied per connection and
    /// applies globally on the connection which implies
    /// all JSON-RPC messages.
    ///
    /// For example if a subscription produces plenty of new items
    /// and the client can't keep up then no new messages are handled.
    ///
    /// If this limit is exceeded then the server will "back-off"
    /// and only accept new messages once the client reads pending messages.
    ///
    /// # Panics
    ///
    /// Panics if the buffer capacity is 0.
    pub fn set_message_buffer_capacity(mut self, c: u32) -> Self {
        self.settings.message_buffer_capacity = c;
        self
    }

    /// Configure a custom [`tokio::runtime::Handle`] to run the server on.
    ///
    /// Default: [`tokio::spawn`]
    pub fn custom_tokio_runtime(mut self, rt: tokio::runtime::Handle) -> Self {
        self.settings.tokio_runtime = Some(rt);
        self
    }

    /// Configure custom `subscription ID` provider for the server to use
    /// to when getting new subscription calls.
    ///
    /// You may choose static dispatch or dynamic dispatch because
    /// `IdProvider` is implemented for `Box<T>`.
    ///
    /// Default: [`RandomIntegerIdProvider`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use jsonrpsee::server::RandomStringIdProvider;
    /// use reth_ipc::server::Builder;
    ///
    /// // static dispatch
    /// let builder1 = Builder::default().set_id_provider(RandomStringIdProvider::new(16));
    ///
    /// // or dynamic dispatch
    /// let builder2 = Builder::default().set_id_provider(Box::new(RandomStringIdProvider::new(16)));
    /// ```
    pub fn set_id_provider<I: IdProvider + 'static>(mut self, id_provider: I) -> Self {
        self.id_provider = Arc::new(id_provider);
        self
    }

    /// Configure a custom [`tower::ServiceBuilder`] middleware for composing layers to be applied
    /// to the RPC service.
    ///
    /// Default: No tower layers are applied to the RPC service.
    ///
    /// # Examples
    ///
    /// ```rust
    /// #[tokio::main]
    /// async fn main() {
    ///     let builder = tower::ServiceBuilder::new();
    ///
    ///     let server =
    ///         reth_ipc::server::Builder::default().set_http_middleware(builder).build("/tmp/my-uds");
    /// }
    /// ```
    pub fn set_http_middleware<T>(
        self,
        service_builder: tower::ServiceBuilder<T>,
    ) -> Builder<T, RpcMiddleware> {
        Builder {
            settings: self.settings,
            id_provider: self.id_provider,
            http_middleware: service_builder,
            rpc_middleware: self.rpc_middleware,
        }
    }

    /// Enable middleware that is invoked on every JSON-RPC call.
    ///
    /// The middleware itself is very similar to the `tower middleware` but
    /// it has a different service trait which takes &self instead &mut self
    /// which means that you can't use built-in middleware from tower.
    ///
    /// Another consequence of `&self` is that you must wrap any of the middleware state in
    /// a type which is Send and provides interior mutability such `Arc<Mutex>`.
    ///
    /// The builder itself exposes a similar API as the [`tower::ServiceBuilder`]
    /// where it is possible to compose layers to the middleware.
    ///
    /// ```
    /// use std::{
    ///     net::SocketAddr,
    ///     sync::{
    ///         atomic::{AtomicUsize, Ordering},
    ///         Arc,
    ///     },
    ///     time::Instant,
    /// };
    ///
    /// use futures_util::future::BoxFuture;
    /// use jsonrpsee::{
    ///     server::{middleware::rpc::RpcServiceT, ServerBuilder},
    ///     types::Request,
    ///     MethodResponse,
    /// };
    /// use reth_ipc::server::{Builder, RpcServiceBuilder};
    ///
    /// #[derive(Clone)]
    /// struct MyMiddleware<S> {
    ///     service: S,
    ///     count: Arc<AtomicUsize>,
    /// }
    ///
    /// impl<'a, S> RpcServiceT<'a> for MyMiddleware<S>
    /// where
    ///     S: RpcServiceT<'a> + Send + Sync + Clone + 'static,
    /// {
    ///     type Future = BoxFuture<'a, MethodResponse>;
    ///
    ///     fn call(&self, req: Request<'a>) -> Self::Future {
    ///         tracing::info!("MyMiddleware processed call {}", req.method);
    ///         let count = self.count.clone();
    ///         let service = self.service.clone();
    ///
    ///         Box::pin(async move {
    ///             let rp = service.call(req).await;
    ///             // Modify the state.
    ///             count.fetch_add(1, Ordering::Relaxed);
    ///             rp
    ///         })
    ///     }
    /// }
    ///
    /// // Create a state per connection
    /// // NOTE: The service type can be omitted once `start` is called on the server.
    /// let m = RpcServiceBuilder::new().layer_fn(move |service: ()| MyMiddleware {
    ///     service,
    ///     count: Arc::new(AtomicUsize::new(0)),
    /// });
    /// let builder = Builder::default().set_rpc_middleware(m);
    /// ```
    pub fn set_rpc_middleware<T>(
        self,
        rpc_middleware: RpcServiceBuilder<T>,
    ) -> Builder<HttpMiddleware, T> {
        Builder {
            settings: self.settings,
            id_provider: self.id_provider,
            rpc_middleware,
            http_middleware: self.http_middleware,
        }
    }

    /// Finalize the configuration of the server. Consumes the [`Builder`].
    pub fn build(self, endpoint: impl AsRef<str>) -> IpcServer<HttpMiddleware, RpcMiddleware> {
        let endpoint = Endpoint::new(endpoint.as_ref().to_string());
        self.build_with_endpoint(endpoint)
    }

    /// Finalize the configuration of the server. Consumes the [`Builder`].
    pub fn build_with_endpoint(
        self,
        endpoint: Endpoint,
    ) -> IpcServer<HttpMiddleware, RpcMiddleware> {
        IpcServer {
            endpoint,
            cfg: self.settings,
            id_provider: self.id_provider,
            http_middleware: self.http_middleware,
            rpc_middleware: self.rpc_middleware,
        }
    }
}

/// Server handle.
///
/// When all [`jsonrpsee::server::StopHandle`]'s have been `dropped` or `stop` has been called
/// the server will be stopped.
#[derive(Debug, Clone)]
pub struct ServerHandle(Arc<watch::Sender<()>>);

impl ServerHandle {
    /// Create a new server handle.
    pub(crate) fn new(tx: watch::Sender<()>) -> Self {
        Self(Arc::new(tx))
    }

    /// Tell the server to stop without waiting for the server to stop.
    pub fn stop(&self) -> Result<(), AlreadyStoppedError> {
        self.0.send(()).map_err(|_| AlreadyStoppedError)
    }

    /// Wait for the server to stop.
    pub async fn stopped(self) {
        self.0.closed().await
    }

    /// Check if the server has been stopped.
    pub fn is_stopped(&self) -> bool {
        self.0.is_closed()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::client::IpcClientBuilder;
    use futures::future::{select, Either};
    use jsonrpsee::{
        core::client::{ClientT, Subscription, SubscriptionClientT},
        rpc_params,
        types::Request,
        PendingSubscriptionSink, RpcModule, SubscriptionMessage,
    };
    use parity_tokio_ipc::dummy_endpoint;
    use tokio::sync::broadcast;
    use tokio_stream::wrappers::BroadcastStream;

    async fn pipe_from_stream_with_bounded_buffer(
        pending: PendingSubscriptionSink,
        stream: BroadcastStream<usize>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let sink = pending.accept().await.unwrap();
        let closed = sink.closed();

        futures::pin_mut!(closed, stream);

        loop {
            match select(closed, stream.next()).await {
                // subscription closed.
                Either::Left((_, _)) => break Ok(()),

                // received new item from the stream.
                Either::Right((Some(Ok(item)), c)) => {
                    let notif = SubscriptionMessage::from_json(&item)?;

                    // NOTE: this will block until there a spot in the queue
                    // and you might want to do something smarter if it's
                    // critical that "the most recent item" must be sent when it is produced.
                    if sink.send(notif).await.is_err() {
                        break Ok(())
                    }

                    closed = c;
                }

                // Send back back the error.
                Either::Right((Some(Err(e)), _)) => break Err(e.into()),

                // Stream is closed.
                Either::Right((None, _)) => break Ok(()),
            }
        }
    }

    // Naive example that broadcasts the produced values to all active subscribers.
    fn produce_items(tx: broadcast::Sender<usize>) {
        for c in 1..=100 {
            std::thread::sleep(std::time::Duration::from_millis(1));
            let _ = tx.send(c);
        }
    }

    #[tokio::test]
    async fn test_rpc_request() {
        let endpoint = dummy_endpoint();
        let server = Builder::default().build(&endpoint);
        let mut module = RpcModule::new(());
        let msg = r#"{"jsonrpc":"2.0","id":83,"result":"0x7a69"}"#;
        module.register_method("eth_chainId", move |_, _| msg).unwrap();
        let handle = server.start(module).await.unwrap();
        tokio::spawn(handle.stopped());

        let client = IpcClientBuilder::default().build(endpoint).await.unwrap();
        let response: String = client.request("eth_chainId", rpc_params![]).await.unwrap();
        assert_eq!(response, msg);
    }

    #[tokio::test]
    async fn test_ipc_modules() {
        reth_tracing::init_test_tracing();
        let endpoint = dummy_endpoint();
        let server = Builder::default().build(&endpoint);
        let mut module = RpcModule::new(());
        let msg = r#"{"admin":"1.0","debug":"1.0","engine":"1.0","eth":"1.0","ethash":"1.0","miner":"1.0","net":"1.0","rpc":"1.0","txpool":"1.0","web3":"1.0"}"#;
        module.register_method("rpc_modules", move |_, _| msg).unwrap();
        let handle = server.start(module).await.unwrap();
        tokio::spawn(handle.stopped());

        let client = IpcClientBuilder::default().build(endpoint).await.unwrap();
        let response: String = client.request("rpc_modules", rpc_params![]).await.unwrap();
        assert_eq!(response, msg);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_rpc_subscription() {
        let endpoint = dummy_endpoint();
        let server = Builder::default().build(&endpoint);
        let (tx, _rx) = broadcast::channel::<usize>(16);

        let mut module = RpcModule::new(tx.clone());
        std::thread::spawn(move || produce_items(tx));

        module
            .register_subscription(
                "subscribe_hello",
                "s_hello",
                "unsubscribe_hello",
                |_, pending, tx| async move {
                    let rx = tx.subscribe();
                    let stream = BroadcastStream::new(rx);
                    pipe_from_stream_with_bounded_buffer(pending, stream).await?;
                    Ok(())
                },
            )
            .unwrap();

        let handle = server.start(module).await.unwrap();
        tokio::spawn(handle.stopped());

        let client = IpcClientBuilder::default().build(endpoint).await.unwrap();
        let sub: Subscription<usize> =
            client.subscribe("subscribe_hello", rpc_params![], "unsubscribe_hello").await.unwrap();

        let items = sub.take(16).collect::<Vec<_>>().await;
        assert_eq!(items.len(), 16);
    }

    #[tokio::test]
    async fn test_rpc_middleware() {
        #[derive(Clone)]
        struct ModifyRequestIf<S>(S);

        impl<'a, S> RpcServiceT<'a> for ModifyRequestIf<S>
        where
            S: Send + Sync + RpcServiceT<'a>,
        {
            type Future = S::Future;

            fn call(&self, mut req: Request<'a>) -> Self::Future {
                // Re-direct all calls that isn't `say_hello` to `say_goodbye`
                if req.method == "say_hello" {
                    req.method = "say_goodbye".into();
                } else if req.method == "say_goodbye" {
                    req.method = "say_hello".into();
                }

                self.0.call(req)
            }
        }

        reth_tracing::init_test_tracing();
        let endpoint = dummy_endpoint();

        let rpc_middleware = RpcServiceBuilder::new().layer_fn(ModifyRequestIf);
        let server = Builder::default().set_rpc_middleware(rpc_middleware).build(&endpoint);

        let mut module = RpcModule::new(());
        let goodbye_msg = r#"{"jsonrpc":"2.0","id":1,"result":"goodbye"}"#;
        let hello_msg = r#"{"jsonrpc":"2.0","id":2,"result":"hello"}"#;
        module.register_method("say_hello", move |_, _| hello_msg).unwrap();
        module.register_method("say_goodbye", move |_, _| goodbye_msg).unwrap();
        let handle = server.start(module).await.unwrap();
        tokio::spawn(handle.stopped());

        let client = IpcClientBuilder::default().build(endpoint).await.unwrap();
        let say_hello_response: String = client.request("say_hello", rpc_params![]).await.unwrap();
        let say_goodbye_response: String =
            client.request("say_goodbye", rpc_params![]).await.unwrap();

        assert_eq!(say_hello_response, goodbye_msg);
        assert_eq!(say_goodbye_response, hello_msg);
    }
}
