//! Live, metadata-only observability of connected tunnels.
//!
//! [`Control`] is threaded through the accept loop and notified when a tunnel
//! comes up / goes down. With the `dynamic` feature it maintains a registry and
//! a broadcast channel (surfaced by [`crate::TunnelServer::tunnels`] and
//! [`crate::TunnelServer::subscribe`]); without the feature it is a zero-sized
//! no-op, so the self-host build carries none of it.
//!
//! By construction the observable surface ([`TunnelInfo`], [`ControlEvent`])
//! carries only who/when/where — never tunnel payload.

use std::net::SocketAddr;

/// Metadata about one connected tunnel. Never carries application payload.
// Fields are read only under the `dynamic` feature (the no-op `Control` ignores
// the value); without it the struct only shapes the no-op signature.
#[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    pub client_name: String,
    pub peer: SocketAddr,
    pub hostnames: Vec<String>,
}

/// A metadata-only observability event. By construction it cannot carry tunnel
/// payload — only identity / endpoint / hostnames.
#[cfg(feature = "dynamic")]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ControlEvent {
    TunnelUp {
        client_name: String,
        peer: SocketAddr,
        hostnames: Vec<String>,
    },
    TunnelDown {
        client_name: String,
        peer: SocketAddr,
    },
}

#[cfg(feature = "dynamic")]
mod imp {
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};

    use tokio::sync::broadcast;

    use super::{ControlEvent, TunnelInfo};

    /// Bound on the live-event channel. A slow subscriber that lags past this
    /// loses the oldest events (broadcast semantics) rather than stalling the
    /// hot path.
    const EVENT_CAPACITY: usize = 256;

    #[derive(Clone)]
    pub struct Control {
        inner: Arc<Inner>,
    }

    struct Inner {
        events: broadcast::Sender<ControlEvent>,
        tunnels: RwLock<HashMap<usize, TunnelInfo>>,
    }

    impl Control {
        pub fn new() -> Self {
            let (events, _) = broadcast::channel(EVENT_CAPACITY);
            Self {
                inner: Arc::new(Inner {
                    events,
                    tunnels: RwLock::new(HashMap::new()),
                }),
            }
        }

        /// Record a tunnel as live and emit `TunnelUp`.
        pub fn register(&self, stable_id: usize, info: TunnelInfo) {
            let event = ControlEvent::TunnelUp {
                client_name: info.client_name.clone(),
                peer: info.peer,
                hostnames: info.hostnames.clone(),
            };
            self.inner
                .tunnels
                .write()
                .expect("control lock poisoned")
                .insert(stable_id, info);
            let _ = self.inner.events.send(event);
        }

        /// Drop a tunnel from the registry and emit `TunnelDown` (only if it was
        /// registered).
        pub fn unregister(&self, stable_id: usize) {
            let removed = self
                .inner
                .tunnels
                .write()
                .expect("control lock poisoned")
                .remove(&stable_id);
            if let Some(info) = removed {
                let _ = self.inner.events.send(ControlEvent::TunnelDown {
                    client_name: info.client_name,
                    peer: info.peer,
                });
            }
        }

        /// Snapshot of currently connected tunnels (metadata only).
        pub fn tunnels(&self) -> Vec<TunnelInfo> {
            self.inner
                .tunnels
                .read()
                .expect("control lock poisoned")
                .values()
                .cloned()
                .collect()
        }

        /// Subscribe to the live event stream.
        pub fn subscribe(&self) -> broadcast::Receiver<ControlEvent> {
            self.inner.events.subscribe()
        }
    }
}

#[cfg(not(feature = "dynamic"))]
mod imp {
    use super::TunnelInfo;

    /// Zero-sized no-op when the `dynamic` feature is off.
    #[derive(Clone)]
    pub struct Control;

    impl Control {
        #[inline]
        pub fn new() -> Self {
            Self
        }
        #[inline]
        pub fn register(&self, _stable_id: usize, _info: TunnelInfo) {}
        #[inline]
        pub fn unregister(&self, _stable_id: usize) {}
    }
}

pub use imp::Control;
