use axum::http::StatusCode;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const MESSAGE_LIMIT: usize = 16 * 1024;

pub struct Bucket {
    tokens: f64,
    capacity: f64,
    refill: f64,
    updated: Instant,
}

impl Bucket {
    pub fn new(capacity: f64, refill: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill,
            updated: Instant::now(),
        }
    }

    pub fn take(&mut self) -> bool {
        self.take_at(Instant::now())
    }

    fn take_at(&mut self, now: Instant) -> bool {
        self.tokens = (self.tokens
            + now.saturating_duration_since(self.updated).as_secs_f64() * self.refill)
            .min(self.capacity);
        self.updated = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

struct AgentLimits {
    auth: Bucket,
    hello: Bucket,
    frames: Bucket,
}

pub struct Controls {
    requests: Mutex<Bucket>,
    agents: Mutex<HashMap<String, AgentLimits>>,
    active: Arc<Mutex<HashSet<String>>>,
    pub auth_slots: Arc<Semaphore>,
    http_slots: Arc<Semaphore>,
    event_slots: Arc<Semaphore>,
}

impl Controls {
    pub fn new(ids: impl Iterator<Item = String>) -> Self {
        let agents = ids
            .map(|id| {
                (
                    id,
                    AgentLimits {
                        auth: Bucket::new(20.0, 2.0),
                        hello: Bucket::new(10.0, 0.1),
                        frames: Bucket::new(640.0, 4.0),
                    },
                )
            })
            .collect();
        Self {
            requests: Mutex::new(Bucket::new(1000.0, 500.0)),
            agents: Mutex::new(agents),
            active: Arc::new(Mutex::new(HashSet::new())),
            auth_slots: Arc::new(Semaphore::new(2)),
            http_slots: Arc::new(Semaphore::new(64)),
            event_slots: Arc::new(Semaphore::new(16)),
        }
    }

    pub fn request(&self) -> Result<OwnedSemaphorePermit, StatusCode> {
        if !self
            .requests
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .take()
        {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        self.http_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| StatusCode::TOO_MANY_REQUESTS)
    }

    fn agent_budget(
        &self,
        id: &str,
        select: impl FnOnce(&mut AgentLimits) -> &mut Bucket,
    ) -> Result<(), StatusCode> {
        let mut agents = self
            .agents
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let limits = agents.get_mut(id).ok_or(StatusCode::UNAUTHORIZED)?;
        if select(limits).take() {
            Ok(())
        } else {
            Err(StatusCode::TOO_MANY_REQUESTS)
        }
    }

    pub fn authentication(&self, id: &str) -> Result<(), StatusCode> {
        self.agent_budget(id, |a| &mut a.auth)
    }

    pub fn hello(&self, id: &str) -> Result<(), StatusCode> {
        self.agent_budget(id, |a| &mut a.hello)
    }

    pub fn frame(&self, id: &str) -> Result<(), StatusCode> {
        self.agent_budget(id, |a| &mut a.frames)
    }

    pub fn connection(&self, id: &str) -> Result<AgentConnection, StatusCode> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if !active.insert(id.to_owned()) {
            return Err(StatusCode::CONFLICT);
        }
        Ok(AgentConnection {
            active: self.active.clone(),
            id: id.to_owned(),
        })
    }

    pub fn events(&self) -> Result<OwnedSemaphorePermit, StatusCode> {
        self.event_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| StatusCode::TOO_MANY_REQUESTS)
    }
}

pub struct AgentConnection {
    active: Arc<Mutex<HashSet<String>>>,
    id: String,
}

impl Drop for AgentConnection {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            active.remove(&self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bursts_are_bounded_and_refill_over_time() {
        let mut bucket = Bucket::new(301.0, 1.0);
        let now = bucket.updated;
        for _ in 0..301 {
            assert!(bucket.take_at(now));
        }
        assert!(!bucket.take_at(now));
        assert!(bucket.take_at(now + Duration::from_secs(1)));
        assert!(!bucket.take_at(now + Duration::from_secs(1)));
    }

    #[test]
    fn connections_release_and_limits_do_not_grow_for_unknown_ids() {
        let limits = Controls::new(["a".to_owned(), "b".to_owned()].into_iter());
        let connection = limits.connection("a").unwrap();
        assert_eq!(limits.connection("a").err(), Some(StatusCode::CONFLICT));
        drop(connection);
        assert!(limits.connection("a").is_ok());
        assert_eq!(
            limits.authentication("unknown"),
            Err(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(limits.agents.lock().unwrap().len(), 2);
        let held: Vec<_> = (0..16).map(|_| limits.events().unwrap()).collect();
        assert_eq!(limits.events().err(), Some(StatusCode::TOO_MANY_REQUESTS));
        drop(held);
        assert!(limits.events().is_ok());
    }
}
