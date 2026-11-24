//! Read-only second-stage F-18 review. No network or configuration writes.
use crate::camouflage_dual_batch::{DualBatchReport, MAX_DUAL_BATCH};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

const EVIDENCE_TTL: Duration = Duration::from_secs(60);

pub(crate) fn evidence_fresh(started_at: Option<Instant>, now: Instant) -> bool {
    started_at
        .and_then(|at| now.checked_duration_since(at))
        .is_some_and(|age| age <= EVIDENCE_TTL)
}

#[derive(Default)]
pub(crate) struct ReviewCursor {
    index: usize,
    open: bool,
}

impl ReviewCursor {
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    pub(crate) fn move_by(&mut self, count: usize, forward: bool) {
        if !self.open && count != 0 {
            self.index = self.index.min(count - 1);
            self.index = if forward {
                (self.index + 1) % count
            } else {
                (self.index + count - 1) % count
            };
        }
    }

    pub(crate) fn marker(&self, index: usize) -> &'static str {
        if index == self.index {
            ">"
        } else {
            " "
        }
    }

    pub(crate) fn open(&mut self, report: &DualBatchReport) {
        self.open = self.index < report.results.len();
    }

    pub(crate) fn close(&mut self) -> bool {
        std::mem::take(&mut self.open)
    }

    pub(crate) fn is_open(&self) -> bool {
        self.open
    }

    pub(crate) fn body(
        &self,
        report: &DualBatchReport,
        selected: &[IpAddr],
        name: &str,
        started_at: Option<Instant>,
        dns_fresh: bool,
    ) -> String {
        let mut out =
            String::from("F-18: шаг 2 — проверка выбранного кандидата (только просмотр)\n");
        let exact = matches_selection(report, selected);
        let fresh = evidence_fresh(started_at, Instant::now()) && dns_fresh;
        if let Some(entry) = report.results.get(self.index) {
            out.push_str(&format!("Адрес: {}  SNI: {name}\n", entry.address));
            if let Ok(observation) = &entry.result {
                if exact && observation.address == entry.address {
                    out.push_str(&format!(
                        "TLS/H2: {}  QUIC/H3: {}\n",
                        if observation.h2_verified() {
                            "подтверждён"
                        } else {
                            "отказ/Unknown"
                        },
                        if observation.h3_verified() {
                            "подтверждён"
                        } else {
                            "отказ/Unknown"
                        },
                    ));
                    if fresh {
                        out.push_str(transport_review(
                            observation.h2_verified(),
                            observation.h3_verified(),
                        ));
                    }
                }
            }
            if !exact || !entry.result.as_ref().is_ok_and(|r| r.h2_verified()) {
                out.push_str("ОТКАЗ: нет обязательного подтверждённого TLS/H2 наблюдения.\n");
            }
        }
        if !exact {
            out.push_str("ОТКАЗ: отчёт не соответствует точному списку согласованных адресов.\n");
        }
        if !fresh {
            out.push_str("ОТКАЗ: измерение или DNS pin устарели/неизвестны; требуется новая проверка с согласием.\n");
        }
        out.push_str("Apply ЗАБЛОКИРОВАН: security mode, независимый server identity, HTTP/3 semantics и security review не готовы.\nКонфигурация, runtime, ключи и приглашения не изменены.\nEsc/n: к отчёту; y не применяет настройки.");
        out
    }
}

// H3 is optional in the target contract. The H2 probe requires X25519,
// but neither transport observation proves HTTP application semantics,
// authorization or REALITY readiness.
fn transport_review(h2: bool, h3: bool) -> &'static str {
    match (h2, h3) {
        (true, true) => "Оба TLS/ALPN наблюдения актуальны. Это не проверка HTTP/3 или REALITY.\n",
        (true, false) => "TLS/H2 подтверждён (TLS 1.3/X25519). H3 не подтверждён; отсутствие H3 само по себе не исключает H2-кандидат.\n",
        (false, _) => "TLS/H2 не подтверждён; H3 не заменяет обязательную проверку H2.\n",
    }
}

fn matches_selection(report: &DualBatchReport, selected: &[IpAddr]) -> bool {
    if selected.is_empty()
        || selected.len() > MAX_DUAL_BATCH
        || report.results.len() != selected.len()
    {
        return false;
    }
    let expected: HashSet<_> = selected
        .iter()
        .map(|ip| SocketAddr::new(*ip, 443))
        .collect();
    let actual: HashSet<_> = report.results.iter().map(|entry| entry.address).collect();
    expected.len() == selected.len()
        && actual.len() == selected.len()
        && actual == expected
        && report.results.iter().all(|entry| match &entry.result {
            Ok(value) => value.address == entry.address,
            Err(_) => true,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{camouflage_dual::DualProbeError, camouflage_dual_batch::DualBatchOutcome};

    fn report(ip: IpAddr) -> DualBatchReport {
        DualBatchReport {
            results: vec![DualBatchOutcome {
                address: SocketAddr::new(ip, 443),
                result: Err(DualProbeError::NotApproved),
            }],
        }
    }

    #[test]
    fn preview_refuses_stale_future_and_wrong_scope_without_activation() {
        let ip: IpAddr = "93.184.216.10".parse().unwrap();
        let other: IpAddr = "93.184.216.11".parse().unwrap();
        let report = report(ip);
        let mut cursor = ReviewCursor::default();
        cursor.open(&report);
        assert!(cursor.is_open());
        for time in [
            None,
            Some(Instant::now() - Duration::from_secs(61)),
            Some(Instant::now() + Duration::from_secs(5)),
        ] {
            let text = cursor.body(&report, &[ip], "example.org", time, true);
            assert!(text.contains("устарели/неизвестны"));
            assert!(text.contains("Apply ЗАБЛОКИРОВАН"));
        }
        let text = cursor.body(&report, &[other], "example.org", Some(Instant::now()), true);
        assert!(text.contains("не соответствует точному списку"));
        let text = cursor.body(&report, &[ip], "example.org", Some(Instant::now()), false);
        assert!(text.contains("устарели/неизвестны"));
        assert!(cursor.close());
        assert!(!cursor.is_open());
    }

    #[test]
    fn h3_optional_evidence_does_not_claim_readiness() {
        assert!(transport_review(true, false).contains("не исключает H2-кандидат"));
        assert!(transport_review(false, true).contains("не заменяет обязательную"));
        assert!(transport_review(true, true).contains("не проверка HTTP/3 или REALITY"));
        assert!(transport_review(false, false).contains("TLS/H2 не подтверждён"));
    }

    #[test]
    fn freshness_boundary_is_inclusive_and_future_refused() {
        let start = Instant::now();
        assert!(evidence_fresh(Some(start), start + Duration::from_secs(60)));
        assert!(!evidence_fresh(
            Some(start),
            start + Duration::from_millis(60_001)
        ));
        assert!(!evidence_fresh(
            Some(start + Duration::from_millis(1)),
            start
        ));
        assert!(!evidence_fresh(None, start));
    }

    #[test]
    fn duplicate_results_and_wrong_port_are_not_exact() {
        let ip: IpAddr = "93.184.216.10".parse().unwrap();
        let other: IpAddr = "93.184.216.11".parse().unwrap();
        let mut report = report(ip);
        assert!(matches_selection(&report, &[ip]));
        report.results.push(report.results[0].clone());
        assert!(!matches_selection(&report, &[ip, other]));
        assert!(!matches_selection(&report, &[ip, ip]));
        report.results.pop();
        report.results[0].address.set_port(444);
        assert!(!matches_selection(&report, &[ip]));
    }
}
