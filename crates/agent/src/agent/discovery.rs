//! Kubernetes service discovery: sending the discovered Services to StatusTick.
use super::*;

impl Agent {
    /// Kubernetes discovery: `desired` gives the monitors to send, None until every namespace was listed.
    pub fn use_discovery(&self, desired: Arc<dyn Fn() -> Option<Vec<Value>> + Send + Sync>) {
        self.lock().discovery.desired = Some(desired);
    }

    /// A Service changed, or the resync is due: the full set goes to StatusTick after [wait] ms, and again on failure.
    pub fn discovery_changed(self: &Arc<Self>, wait: u64) {
        {
            let mut inner = self.lock();
            if inner.discovery.desired.is_none() || self.stopped() {
                return;
            }
            inner.discovery.dirty = true;
            if inner.discovery.timer {
                return;
            }
            inner.discovery.timer = true;
        }
        let agent = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(wait)).await;
            agent.lock().discovery.timer = false;
            agent.start_discovery();
        });
    }

    pub fn discovery_soon(self: &Arc<Self>) {
        self.discovery_changed(DISCOVERY_DEBOUNCE_MS);
    }

    pub(super) fn start_discovery(self: &Arc<Self>) {
        {
            let mut inner = self.lock();
            if inner.discovery.desired.is_none()
                || inner.discovery.sending
                || self.stopped()
                || self.client.agent_id().is_none()
                || inner.outage_since.is_some()
            {
                return;
            }
            inner.discovery.sending = true;
        }
        let agent = self.clone();
        tokio::spawn(async move {
            agent.send_discovery().await;
            agent.lock().discovery.sending = false;
        });
    }

    pub(super) async fn send_discovery(self: &Arc<Self>) {
        let desired = self.lock().discovery.desired.clone();
        let Some(monitors) = desired.and_then(|desired| desired()) else { return };
        let limit_line = {
            let mut inner = self.lock();
            inner.discovery.dirty = false;
            (monitors.len() > MAX_DISCOVERED_PER_CALL && !inner.discovery.limit_logged).then(|| {
                inner.discovery.limit_logged = true;
                format!("Kubernetes discovery: {} annotated Services; only the first {MAX_DISCOVERED_PER_CALL} by namespace and name are sent.", monitors.len())
            })
        };
        if let Some(line) = limit_line {
            self.log(&line);
        }
        let sent: Vec<Value> = monitors.into_iter().take(MAX_DISCOVERED_PER_CALL).collect();
        match self.client.put_discovery(&json!({ "monitors": sent })).await {
            Ok(answer) if answer.get("busy") == Some(&Value::Bool(true)) => self.discovery_changed(DISCOVERY_BUSY_RETRY_MS),
            Ok(Value::Null) => {}
            Ok(answer) => self.log_discovery(&answer),
            Err(error) => {
                self.log(&format!(
                    "Kubernetes discovery: StatusTick did not take the monitors: {}. Trying again in {} seconds.",
                    error.describe(),
                    DISCOVERY_RETRY_MS / 1000
                ));
                self.discovery_changed(DISCOVERY_RETRY_MS);
            }
        }
    }

    pub(super) fn log_discovery(&self, answer: &Value) {
        let keys = |name: &str| -> Vec<String> {
            answer.get(name).and_then(Value::as_array).map(|keys| keys.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default()
        };
        let changes: Vec<String> = ["created", "updated", "paused", "resumed"]
            .iter()
            .map(|verb| (verb, keys(verb)))
            .filter(|(_, keys)| !keys.is_empty())
            .map(|(verb, keys)| {
                let more = if keys.len() > MAX_SKIPPED_LOGGED { format!(" and {} more", keys.len() - MAX_SKIPPED_LOGGED) } else { String::new() };
                format!("{verb} {}{more}", keys.iter().take(MAX_SKIPPED_LOGGED).cloned().collect::<Vec<_>>().join(", "))
            })
            .collect();
        if !changes.is_empty() {
            self.log(&format!("Kubernetes discovery: StatusTick {}.", changes.join("; ")));
        }
        let skipped: Vec<Value> = answer.get("skipped").and_then(Value::as_array).cloned().unwrap_or_default();
        let signature = Value::from(skipped.clone()).to_string();
        {
            let mut inner = self.lock();
            if inner.discovery.skipped == signature {
                return;
            }
            inner.discovery.skipped = signature;
        }
        for entry in skipped.iter().take(MAX_SKIPPED_LOGGED) {
            let text = |name: &str| entry.get(name).and_then(Value::as_str).unwrap_or("").to_string();
            let message = text("message");
            let detail = if message.is_empty() { String::new() } else { format!(" ({message})") };
            self.log(&format!("Kubernetes discovery: {} is not monitored: {}{detail}.", text("key"), text("reason")));
        }
        let over = skipped.iter().filter(|entry| entry.get("reason").and_then(Value::as_str) == Some("discovery.limit_reached")).count();
        if over > 0 {
            let limit = answer.get("limit").map(|limit| limit.to_string()).unwrap_or_default();
            self.log(&format!("Kubernetes discovery: {over} Services are over this location's limit of {limit} discovered monitors."));
        } else if skipped.len() > MAX_SKIPPED_LOGGED {
            self.log(&format!("Kubernetes discovery: {} more Services are not monitored.", skipped.len() - MAX_SKIPPED_LOGGED));
        }
    }
}
