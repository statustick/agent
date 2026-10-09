//! The heartbeat relay: buffering pings from inside the network and uploading them.
use super::*;

impl Agent {
    /// A ping from the relay port, kept with the time it arrived and sent to StatusTick within about a second.
    pub fn relay_ping(self: &Arc<Self>, ping_id: &str, kind: &str, run: Option<&str>) -> RelayAnswer {
        {
            let mut inner = self.lock();
            let Some(relay) = inner.relay.as_mut() else { return RelayAnswer::NotReady };
            if !relay.list.received() {
                return RelayAnswer::NotReady;
            }
            if !relay.list.allows(ping_id) {
                return RelayAnswer::Unknown;
            }
            let mut ping = json!({ "pingId": ping_id, "kind": kind, "at": iso(now_ms()) });
            if let Some(run) = run {
                ping["run"] = Value::from(run);
            }
            relay.pings.add(ping);
        }
        self.schedule_relay();
        RelayAnswer::Accepted
    }

    pub(super) fn schedule_relay(self: &Arc<Self>) {
        {
            let mut inner = self.lock();
            if inner.relay_timer || inner.relaying {
                return;
            }
            inner.relay_timer = true;
        }
        let agent = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(RELAY_BATCH).await;
            agent.lock().relay_timer = false;
            agent.start_relay();
        });
    }

    pub(super) fn start_relay(self: &Arc<Self>) {
        {
            let mut inner = self.lock();
            if inner.relaying || self.stopped() || inner.relay.as_ref().is_none_or(|relay| relay.pings.count() == 0) {
                return;
            }
            inner.relaying = true;
        }
        let agent = self.clone();
        tokio::spawn(async move {
            agent.relay_upload().await;
            agent.lock().relaying = false;
            agent.work_done.notify_waiters();
        });
    }

    /// Sends the relayed pings oldest first while StatusTick answers; while the agent is offline they stay buffered.
    pub(super) async fn relay_upload(&self) {
        let mut failures = 0;
        loop {
            let (batch, request) = {
                let inner = self.lock();
                let Some(relay) = inner.relay.as_ref() else { return };
                if relay.pings.count() == 0 || inner.outage_since.is_some() || self.client.agent_id().is_none() || inner.relay_refused {
                    return;
                }
                let batch = relay.pings.batch(MAX_RELAYED_PINGS_PER_CALL, MAX_LATE_RESULTS_BYTES);
                let pings: Vec<Value> = batch.iter().map(|(_, ping)| ping.clone()).collect();
                (batch, json!({ "pings": pings, "dropped": relay.pings.dropped }))
            };
            match self.client.post_relayed_pings(&request).await {
                Ok(answer) => {
                    let count = |name: &str| answer.get(name).and_then(Value::as_array).map(Vec::len).unwrap_or(0);
                    self.metrics.relayed("accepted", count("accepted"));
                    self.metrics.relayed("rejected", count("rejected"));
                    let done = Self::answered(&answer, &batch);
                    if let Some(relay) = self.lock().relay.as_mut() {
                        relay.pings.remove(&done);
                    }
                    if done.is_empty() {
                        return;
                    }
                    failures = 0;
                }
                Err(error) => {
                    self.metrics.relayed("failed", batch.len());
                    if !error.is_retryable() {
                        self.lock().relay_refused = true;
                        self.log(&format!(
                            "StatusTick refused the relayed heartbeat pings: {}. They stay buffered until the agent connects again.",
                            error.describe()
                        ));
                        return;
                    }
                    if self.stopped() {
                        return;
                    }
                    let delay = error.retry_after_ms().unwrap_or_else(|| backoff_delay(failures));
                    failures += 1;
                    self.wait(delay).await;
                }
            }
        }
    }
}
