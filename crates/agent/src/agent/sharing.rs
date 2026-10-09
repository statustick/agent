//! Sharing agent health with StatusTick.
use super::*;

impl Agent {
    /// STATUSTICK_SHARE_METRICS wins; otherwise StatusTick's answer carries the agent's setting. Logs each change.
    pub(super) fn share_metrics(&self, from_status_tick: Option<bool>) {
        let sharing = match self.config.settings.share_metrics {
            Some(false) => false,
            Some(true) => true,
            None => from_status_tick == Some(true),
        };
        {
            let mut inner = self.lock();
            if inner.sharing_metrics == sharing {
                return;
            }
            inner.sharing_metrics = sharing;
        }
        self.log(if sharing {
            "Sharing agent health with StatusTick: on, from the dashboard. It sends its metrics every minute."
        } else {
            "Sharing agent health with StatusTick: off, from the dashboard."
        });
    }

    /// While sharing, the shared metrics once; a failure waits for the next interval and never holds up checks.
    pub(super) async fn push_metrics(&self) {
        let sharing = {
            let inner = self.lock();
            inner.sharing_metrics && inner.outage_since.is_none()
        };
        if !sharing || self.config.settings.share_metrics == Some(false) || self.stopped() || self.client.agent_id().is_none() {
            return;
        }
        let text = self.metrics.shared(&self.snapshot());
        if let Err(error) = self.client.post_metrics(text).await
            && error.status() == Some(403)
        {
            self.share_metrics(Some(false));
        }
    }
}
