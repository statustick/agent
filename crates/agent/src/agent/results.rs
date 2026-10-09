//! Results: posting them, the offline buffer and its repeated jobs, and late results.
use super::*;

impl Agent {
    pub(super) fn queue_result(self: &Arc<Self>, result: Value, expires_at: Option<&str>, late: Option<Value>) {
        let expires_at = expires_at.and_then(|text| chrono::DateTime::parse_from_rfc3339(text).ok()).map(|time| time.timestamp_millis());
        self.lock().pending.push(Pending { result, expires_at, late });
        self.start_flush();
    }

    pub(super) fn start_flush(self: &Arc<Self>) {
        {
            let mut inner = self.lock();
            if inner.flushing {
                return;
            }
            inner.flushing = true;
        }
        let agent = self.clone();
        tokio::spawn(async move {
            agent.flush().await;
            let again = {
                let mut inner = agent.lock();
                inner.flushing = false;
                !inner.pending.is_empty()
            };
            agent.work_done.notify_waiters();
            if again && !agent.stopped() {
                agent.start_flush();
            }
        });
    }

    pub(super) async fn flush(&self) {
        let mut failures = 0;
        loop {
            let batch: Vec<Pending> = {
                let mut inner = self.lock();
                let now = now_ms();
                let mut expired = Vec::new();
                inner.pending.retain_mut(|pending| {
                    let gone = pending.expires_at.is_some_and(|at| at <= now);
                    if gone && let Some(late) = pending.late.take() {
                        expired.push(late);
                    }
                    !gone
                });
                for late in expired {
                    inner.buffer.add(late);
                }
                let count = inner.pending.len().min(MAX_RESULTS_PER_CALL);
                inner.pending.drain(..count).collect()
            };
            if batch.is_empty() {
                return;
            }
            let results: Vec<Value> = batch.iter().map(|pending| pending.result.clone()).collect();
            match self.client.post_results(&results).await {
                Ok(_) => {
                    self.metrics.upload("ok");
                    failures = 0;
                }
                Err(error) => {
                    self.metrics.upload(if error.is_retryable() { "failed" } else { "rejected" });
                    if !error.is_retryable() {
                        continue;
                    }
                    {
                        let mut inner = self.lock();
                        let rest = std::mem::take(&mut inner.pending);
                        inner.pending = batch;
                        inner.pending.extend(rest);
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

    /// After a poll cycle without StatusTick, repeats remembered jobs on their intervals and buffers the results;
    /// stops checking after an hour but keeps the buffer.
    pub(super) fn offline_tick(self: &Arc<Self>) {
        let now = now_ms();
        let due = {
            let mut inner = self.lock();
            let Some(since) = inner.outage_since else { return };
            if self.stopped() || inner.paused {
                return;
            }
            let down = now - since;
            if !inner.offline {
                if down < inner.server.poll_wait_seconds as i64 * 1000 {
                    return;
                }
                inner.offline = true;
                self.client.forget_agent();
                let line = format!(
                    "Offline: no answer from StatusTick for {} seconds. Checking {} monitors on their own schedule for up to an hour and buffering the results.",
                    (down as f64 / 1000.0).round(),
                    inner.memory.size()
                );
                drop(inner);
                self.log(&line);
                inner = self.lock();
            }
            if down >= OFFLINE_CHECKS_FOR_MS {
                if !inner.offline_limit_logged {
                    inner.offline_limit_logged = true;
                    let line = format!("Offline for an hour: stopped checking. {} results stay buffered until StatusTick answers.", inner.buffer.count());
                    drop(inner);
                    self.log(&line);
                }
                return;
            }
            inner.memory.due(now)
        };
        for monitor_id in due {
            if self.slots.free() == 0 {
                break;
            }
            self.run_offline(monitor_id, now);
        }
    }

    pub(super) fn run_offline(self: &Arc<Self>, monitor_id: String, now: i64) {
        let job = {
            let mut inner = self.lock();
            let Some(remembered) = inner.memory.get_mut(&monitor_id) else { return };
            remembered.running = true;
            remembered.next_at = now + remembered.interval_seconds * 1000;
            remembered.job.clone()
        };
        let slot = self.slots.take();
        let agent = self.clone();
        tokio::spawn(async move {
            let entry = crate::jobs::run_job(&job).await;
            drop(slot);
            let mut inner = agent.lock();
            inner.buffer.add(json!({ "monitorId": monitor_id, "checkedAt": iso(now), "result": entry["result"] }));
            if let Some(remembered) = inner.memory.get_mut(&monitor_id) {
                remembered.running = false;
            }
        });
    }

    pub(super) fn end_outage(&self) {
        let line = {
            let mut inner = self.lock();
            let line = match (inner.offline, inner.outage_since) {
                (true, Some(since)) => Some(format!("StatusTick answers again after {} minutes offline.", ((now_ms() - since) as f64 / 60000.0).round())),
                _ => None,
            };
            inner.outage_since = None;
            inner.offline = false;
            inner.offline_limit_logged = false;
            line
        };
        if let Some(line) = line {
            self.log(&line);
        }
    }

    pub(super) fn start_upload(self: &Arc<Self>) {
        let line = {
            let mut inner = self.lock();
            if inner.uploading || inner.upload_refused || self.stopped() || inner.buffer.count() == 0 {
                return;
            }
            inner.uploading = true;
            let dropped =
                if inner.buffer.dropped > 0 { format!(" ({} older ones were dropped: the buffer was full)", inner.buffer.dropped) } else { String::new() };
            format!("Uploading {} results checked while offline{dropped}.", inner.buffer.count())
        };
        self.log(&line);
        let agent = self.clone();
        tokio::spawn(async move {
            agent.upload().await;
            agent.lock().uploading = false;
        });
    }

    pub(super) fn answered(answer: &Value, batch: &[(u64, Value)]) -> Vec<u64> {
        let mut indices: Vec<usize> = answer
            .get("accepted")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_u64).map(|index| index as usize).collect())
            .unwrap_or_default();
        if let Some(rejected) = answer.get("rejected").and_then(Value::as_array) {
            indices.extend(rejected.iter().filter_map(|item| item.get("index").and_then(Value::as_u64)).map(|index| index as usize));
        }
        batch.iter().enumerate().filter(|(index, _)| indices.contains(index)).map(|(_, (id, _))| *id).collect()
    }

    /// Sends the buffer oldest first; results StatusTick accepted or rejected leave it, the rest is sent again.
    pub(super) async fn upload(&self) {
        let mut failures = 0;
        loop {
            let (batch, request) = {
                let inner = self.lock();
                if inner.buffer.count() == 0 || self.stopped() || inner.outage_since.is_some() {
                    break;
                }
                let batch = inner.buffer.batch(MAX_LATE_RESULTS_PER_CALL, MAX_LATE_RESULTS_BYTES);
                let results: Vec<Value> = batch.iter().map(|(_, entry)| entry.clone()).collect();
                let request = json!({ "results": results, "dropped": inner.buffer.dropped, "bufferedSince": inner.buffer.since() });
                (batch, request)
            };
            match self.client.post_late_results(&request).await {
                Ok(answer) => {
                    self.metrics.upload("ok");
                    let done = Self::answered(&answer, &batch);
                    self.lock().buffer.remove(&done);
                    if done.is_empty() {
                        return;
                    }
                    failures = 0;
                }
                Err(error) => {
                    self.metrics.upload(if error.is_retryable() { "failed" } else { "rejected" });
                    if !error.is_retryable() {
                        self.lock().upload_refused = true;
                        self.log(&format!("StatusTick refused the buffered results: {}. They stay buffered until the agent connects again.", error.describe()));
                        return;
                    }
                    let delay = error.retry_after_ms().unwrap_or_else(|| backoff_delay(failures));
                    failures += 1;
                    self.wait(delay).await;
                }
            }
        }
        if self.lock().buffer.count() == 0 {
            self.log("All buffered results are uploaded.");
        }
    }
}
