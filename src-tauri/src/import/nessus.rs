//! Nessus (.nessus v2 XML) importer (roxmltree).
//!
//! Maps `NessusClientData_v2/Report/ReportHost/ReportItem`: `pluginName` (attr)
//! → title, `severity` (attr 0..4) → info/low/medium/high/critical,
//! `description`/`synopsis` child → summary, `solution` child → remediation,
//! `cve` children → cve, `cvss3_base_score`/`cvss_base_score` and
//! `cvss3_vector`/`cvss_vector` children → cvss. Host + port → evidence.

use roxmltree::{Document, Node};

use super::normalize_cve;
use crate::error::{AppError, AppResult};
use crate::models::{
    Evidence, FindingDescription, FindingKind, FindingRemediation, NewFinding, Severity,
};

/// Nessus numeric severity (0..4) → severity. Unknown → info.
fn nessus_severity(raw: &str) -> Severity {
    match raw.trim() {
        "4" => Severity::Critical,
        "3" => Severity::High,
        "2" => Severity::Medium,
        "1" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Text of the first child element named `tag` under `node`, trimmed.
fn child_text(node: Node<'_, '_>, tag: &str) -> Option<String> {
    node.children()
        .find(|c| c.is_element() && c.has_tag_name(tag))
        .and_then(|c| c.text())
        .map(|t| t.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Text of every child element named `tag`.
fn child_texts(node: Node<'_, '_>, tag: &str) -> Vec<String> {
    node.children()
        .filter(|c| c.is_element() && c.has_tag_name(tag))
        .filter_map(|c| c.text())
        .map(|t| t.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn parse(content: &str) -> AppResult<Vec<NewFinding>> {
    let doc = Document::parse(content)
        .map_err(|e| AppError::Import(format!("invalid Nessus XML: {e}")))?;

    let mut findings = Vec::new();

    for host in doc
        .descendants()
        .filter(|n| n.is_element() && n.has_tag_name("ReportHost"))
    {
        let host_name = host
            .attribute("name")
            .map(|s| s.to_string())
            .unwrap_or_default();

        for item in host
            .children()
            .filter(|c| c.is_element() && c.has_tag_name("ReportItem"))
        {
            let severity = nessus_severity(item.attribute("severity").unwrap_or("0"));

            let title = item
                .attribute("pluginName")
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "Nessus finding".to_string());

            let summary = child_text(item, "description")
                .or_else(|| child_text(item, "synopsis"))
                .unwrap_or_else(|| "Imported from Nessus scan.".to_string());

            let fix = child_text(item, "solution").unwrap_or_default();

            // CVE: may appear as multiple <cve> children. Take the first valid.
            let cve = child_texts(item, "cve")
                .into_iter()
                .find_map(|c| normalize_cve(&c));

            // CWE may appear as <cwe> children (numeric).
            let cwe = child_text(item, "cwe").map(|c| {
                let digits: String = c.chars().filter(|d| d.is_ascii_digit()).collect();
                format!("CWE-{digits}")
            });

            let cvss_score = child_text(item, "cvss3_base_score")
                .or_else(|| child_text(item, "cvss_base_score"))
                .and_then(|s| s.parse::<f64>().ok());
            let cvss_vector =
                child_text(item, "cvss3_vector").or_else(|| child_text(item, "cvss_vector"));

            let mut references: Vec<String> = Vec::new();
            references.extend(child_texts(item, "see_also").into_iter().flat_map(|s| {
                s.lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect::<Vec<_>>()
            }));

            let port = item.attribute("port").unwrap_or("");
            let protocol = item.attribute("protocol").unwrap_or("");
            let svc = item.attribute("svc_name").unwrap_or("");
            let location = {
                let mut loc = host_name.clone();
                if !port.is_empty() && port != "0" {
                    loc.push(':');
                    loc.push_str(port);
                }
                if !protocol.is_empty() {
                    loc.push_str(&format!("/{protocol}"));
                }
                if !svc.is_empty() {
                    loc.push_str(&format!(" ({svc})"));
                }
                loc
            };
            let evidence = if location.is_empty() {
                None
            } else {
                Some(Evidence {
                    file: Some(location),
                    start_line: None,
                    end_line: None,
                    snippet: child_text(item, "plugin_output"),
                })
            };

            findings.push(NewFinding {
                title,
                severity,
                confidence: None,
                kind: Some(FindingKind::Sast),
                cwe,
                cve,
                cvss_vector,
                cvss_score,
                triage_status: None,
                triage_note: None,
                description: Some(FindingDescription {
                    summary,
                    ..Default::default()
                }),
                remediation: Some(FindingRemediation {
                    fix,
                    code_patch: None,
                    references: references.clone(),
                }),
                evidence,
                poc: None,
                refs: Some(references),
                tags: Some(vec!["imported".into(), "nessus".into()]),
                retest_status: None,
                retest_date: None,
                custom_fields: None,
                mappings: None,
            });
        }
    }

    Ok(findings)
}
