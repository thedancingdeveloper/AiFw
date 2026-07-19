use std::sync::Arc;

use aifw_common::ids::{IdsAction, IdsAlert, IdsMode};
use aifw_pf::PfBackend;
use tracing::info;

use crate::config::RuntimeConfig;

/// The IDS block table in pf
pub(crate) const IDS_BLOCK_TABLE: &str = "aifw-ids-block";
const IDS_BLOCK_ANCHOR: &str = "aifw-ids";

/// Verdict from the action engine
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Pass the packet (no action)
    Pass,
    /// Alert only (IDS mode or alert action)
    Alert,
    /// Drop the packet (IPS mode + drop action)
    Drop,
    /// Reject the packet — send RST/ICMP unreachable (IPS mode + reject action)
    Reject,
}

/// The action engine determines what happens after a detection match.
/// In IDS mode, all verdicts become alerts. In IPS mode, drops are enforced via pf.
pub struct ActionEngine {
    pf: Arc<dyn PfBackend>,
    config: Arc<RuntimeConfig>,
}

impl ActionEngine {
    /// Create an action engine backed by the given pf backend (for block-table
    /// writes) and runtime config (for the IDS/IPS mode check).
    pub fn new(pf: Arc<dyn PfBackend>, config: Arc<RuntimeConfig>) -> Self {
        Self { pf, config }
    }

    /// Determine the verdict for an alert based on mode and rule action.
    pub fn verdict(&self, alert: &IdsAlert) -> Verdict {
        let mode = self.config.config().mode;

        match mode {
            IdsMode::Ids => {
                // IDS mode: everything is an alert
                Verdict::Alert
            }
            IdsMode::Ips => {
                // IPS mode: enforce the rule action
                match alert.action {
                    IdsAction::Pass => Verdict::Pass,
                    IdsAction::Alert => Verdict::Alert,
                    IdsAction::Drop => Verdict::Drop,
                    IdsAction::Reject => Verdict::Reject,
                }
            }
            IdsMode::Disabled => Verdict::Pass,
        }
    }

    /// Execute the verdict — add to pf block table if needed.
    pub async fn ensure_enforcement(&self) -> crate::Result<()> {
        self.pf
            .load_rules(
                IDS_BLOCK_ANCHOR,
                &[
                    format!("block in quick from <{IDS_BLOCK_TABLE}> to any"),
                    format!("block out quick from <{IDS_BLOCK_TABLE}> to any"),
                ],
            )
            .await?;
        Ok(())
    }

    /// Apply a reactive verdict. This blocks subsequent packets from the
    /// source; passive BPF capture cannot stop the triggering packet.
    pub async fn execute(&self, alert: &IdsAlert, verdict: &Verdict) -> crate::Result<()> {
        match verdict {
            Verdict::Drop | Verdict::Reject => {
                info!(
                    src = %alert.src_ip,
                    sig = %alert.signature_msg,
                    action = %if *verdict == Verdict::Drop { "drop" } else { "reject" },
                    "IPS blocking source"
                );

                self.pf
                    .add_table_entry(IDS_BLOCK_TABLE, alert.src_ip)
                    .await?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Remove an IP from the IDS block table.
    pub async fn unblock(&self, ip: std::net::IpAddr) -> crate::Result<()> {
        self.pf.remove_table_entry(IDS_BLOCK_TABLE, ip).await?;
        Ok(())
    }

    /// Flush the IDS block table.
    pub async fn flush_blocks(&self) -> crate::Result<()> {
        self.pf.flush_table(IDS_BLOCK_TABLE).await?;
        Ok(())
    }
}

impl std::fmt::Debug for ActionEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionEngine").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aifw_common::ids::{IdsSeverity, RuleSource};

    fn test_alert(action: IdsAction) -> IdsAlert {
        IdsAlert::new(
            "Test alert".into(),
            IdsSeverity::HIGH,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "tcp",
            action,
            RuleSource::Custom,
        )
    }

    #[tokio::test]
    async fn test_verdict_ids_mode() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::IdsEngine::migrate(&pool).await.unwrap();

        let config = Arc::new(RuntimeConfig::load(&pool).await.unwrap());

        // Set IDS mode
        let mut cfg = (*config.config()).clone();
        cfg.mode = IdsMode::Ids;
        config.update(cfg);

        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = ActionEngine::new(pf, config);

        // In IDS mode, everything becomes Alert
        assert_eq!(engine.verdict(&test_alert(IdsAction::Drop)), Verdict::Alert);
        assert_eq!(
            engine.verdict(&test_alert(IdsAction::Reject)),
            Verdict::Alert
        );
        assert_eq!(
            engine.verdict(&test_alert(IdsAction::Alert)),
            Verdict::Alert
        );
    }

    #[tokio::test]
    async fn test_verdict_ips_mode() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::IdsEngine::migrate(&pool).await.unwrap();

        let config = Arc::new(RuntimeConfig::load(&pool).await.unwrap());

        let mut cfg = (*config.config()).clone();
        cfg.mode = IdsMode::Ips;
        config.update(cfg);

        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = ActionEngine::new(pf, config);

        assert_eq!(engine.verdict(&test_alert(IdsAction::Drop)), Verdict::Drop);
        assert_eq!(
            engine.verdict(&test_alert(IdsAction::Reject)),
            Verdict::Reject
        );
        assert_eq!(
            engine.verdict(&test_alert(IdsAction::Alert)),
            Verdict::Alert
        );
        assert_eq!(engine.verdict(&test_alert(IdsAction::Pass)), Verdict::Pass);
    }

    #[tokio::test]
    async fn test_reactive_block_lifecycle_ipv4_and_ipv6() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::IdsEngine::migrate(&pool).await.unwrap();
        let config = Arc::new(RuntimeConfig::load(&pool).await.unwrap());
        let pf = Arc::new(aifw_pf::PfMock::new());
        let engine = ActionEngine::new(pf.clone(), config);

        engine.ensure_enforcement().await.unwrap();
        let rules = pf.get_rules(IDS_BLOCK_ANCHOR).await.unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|r| r.contains("<aifw-ids-block>")));

        let v4 = test_alert(IdsAction::Drop);
        engine.execute(&v4, &Verdict::Drop).await.unwrap();
        let mut v6 = test_alert(IdsAction::Reject);
        v6.src_ip = "2001:db8::bad".parse().unwrap();
        engine.execute(&v6, &Verdict::Reject).await.unwrap();
        let entries = pf.get_table_entries(IDS_BLOCK_TABLE).await.unwrap();
        assert_eq!(entries.len(), 2);

        engine.unblock(v4.src_ip).await.unwrap();
        let entries = pf.get_table_entries(IDS_BLOCK_TABLE).await.unwrap();
        assert_eq!(entries.len(), 1);
        engine.flush_blocks().await.unwrap();
        assert!(
            pf.get_table_entries(IDS_BLOCK_TABLE)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
