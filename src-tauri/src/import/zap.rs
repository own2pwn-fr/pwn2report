//! OWASP ZAP JSON-report importer.
//!
//! Maps `site[].alerts[]`: `name`/`alert` → title, `riskcode`/`riskdesc` →
//! severity, `desc` → summary, `solution` → remediation fix, `reference` →
//! references, `cweid` → CWE, and instance URLs → evidence.

use serde_json::Value;

use super::{normalize_cwe, severity_from_label};
use crate::error::{AppError, AppResult};
use crate::models::{Evidence, FindingDescription, FindingKind, FindingRemediation, NewFinding, Severity};

/// ZAP `riskcode` (0=info..3=high) → severity. Falls back to parsing
/// `riskdesc` text, else medium.
fn risk_to_severity(riskcode: Option<&str>, riskdesc: Option<&str>) -> Severity {
    if let Some(code) = riskcode {
        match code.trim() {
            "3" => return Severity::High,
            "2" => return Severity::Medium,
            "1" => return Severity::Low,
            "0" => return Severity::Info,
            _ => {}
        }
    }
    if let Some(desc) = riskdesc {
        // riskdesc looks like "High (Medium)" — take the leading word.
        let head = desc.split_whitespace().next().unwrap_or("");
        return severity_from_label(head);
    }
    Severity::Medium
}

/// Strip simple HTML tags ZAP embeds in desc/solution to keep plain text.
fn strip_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .trim()
        .to_string()
}

fn str_field(alert: &Value, key: &str) -> Option<String> {
    alert.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn alert_to_finding(alert: &Value) -> NewFinding {
    let title = str_field(alert, "name")
        .or_else(|| str_field(alert, "alert"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "ZAP alert".to_string());

    let severity = risk_to_severity(
        alert.get("riskcode").and_then(|v| v.as_str()),
        alert.get("riskdesc").and_then(|v| v.as_str()),
    );

    let summary = str_field(alert, "desc").map(|s| strip_html(&s)).unwrap_or_default();
    let fix = str_field(alert, "solution").map(|s| strip_html(&s)).unwrap_or_default();

    let mut references: Vec<String> = Vec::new();
    if let Some(reference) = str_field(alert, "reference") {
        for line in strip_html(&reference).lines() {
            let t = line.trim();
            if !t.is_empty() {
                references.push(t.to_string());
            }
        }
    }

    let cwe = str_field(alert, "cweid")
        .filter(|s| s != "-1" && !s.is_empty())
        .and_then(|s| normalize_cwe(&s));

    // First instance URI → evidence.
    let evidence = alert
        .get("instances")
        .and_then(|i| i.as_array())
        .and_then(|a| a.first())
        .and_then(|inst| inst.get("uri").and_then(|u| u.as_str()))
        .map(|uri| Evidence {
            file: Some(uri.to_string()),
            start_line: None,
            end_line: None,
            snippet: alert
                .get("instances")
                .and_then(|i| i.as_array())
                .and_then(|a| a.first())
                .and_then(|inst| inst.get("evidence").and_then(|e| e.as_str()))
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        });

    NewFinding {
        title,
        severity,
        confidence: None,
        kind: Some(FindingKind::Sast),
        cwe,
        cve: None,
        cvss_vector: None,
        cvss_score: None,
        triage_status: None,
        triage_note: None,
        description: Some(FindingDescription {
            summary: if summary.is_empty() {
                "Imported from OWASP ZAP report.".into()
            } else {
                summary
            },
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
        tags: Some(vec!["imported".into(), "zap".into()]),
    }
}

pub fn parse(content: &str) -> AppResult<Vec<NewFinding>> {
    let doc: Value = serde_json::from_str(content)
        .map_err(|e| AppError::Import(format!("invalid ZAP JSON: {e}")))?;

    // `site` can be a single object or an array depending on ZAP version.
    let sites: Vec<&Value> = match doc.get("site") {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(obj @ Value::Object(_)) => vec![obj],
        _ => {
            return Err(AppError::Import(
                "ZAP report has no `site` entries".into(),
            ))
        }
    };

    let mut findings = Vec::new();
    for site in sites {
        if let Some(alerts) = site.get("alerts").and_then(|a| a.as_array()) {
            for alert in alerts {
                findings.push(alert_to_finding(alert));
            }
        }
    }
    Ok(findings)
}
