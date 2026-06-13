//! SARIF 2.1.0 importer (covers many SAST tools: Semgrep, CodeQL, etc.).
//!
//! Maps `runs[].results[]` to findings: `message.text` → title/summary,
//! `ruleId` → CWE when the rule's taxa/properties expose one, `level`
//! (error/warning/note) → severity, and the first physical location's
//! file/line → evidence.

use std::collections::HashMap;

use serde_json::Value;

use super::normalize_cwe;
use crate::error::{AppError, AppResult};
use crate::models::{Evidence, FindingDescription, FindingKind, NewFinding, Severity};

/// SARIF `level` → severity. SARIF only defines error/warning/note/none;
/// anything else falls back to medium.
fn level_to_severity(level: &str) -> Severity {
    match level.to_ascii_lowercase().as_str() {
        "error" => Severity::High,
        "warning" => Severity::Medium,
        "note" => Severity::Low,
        "none" => Severity::Info,
        _ => Severity::Medium,
    }
}

/// Try to extract a CWE id from a rule definition's taxa relationships or
/// properties (`tags`, `cwe`, `security-severity` are common carriers).
fn rule_cwe(rule: &Value) -> Option<String> {
    // properties.tags: ["CWE-79", "security", ...]
    if let Some(tags) = rule
        .get("properties")
        .and_then(|p| p.get("tags"))
        .and_then(|t| t.as_array())
    {
        for tag in tags {
            if let Some(s) = tag.as_str() {
                if s.to_ascii_uppercase().contains("CWE") {
                    if let Some(cwe) = normalize_cwe(s) {
                        return Some(cwe);
                    }
                }
            }
        }
    }
    // properties.cwe: "CWE-89" or 89
    if let Some(cwe) = rule.get("properties").and_then(|p| p.get("cwe")) {
        if let Some(s) = cwe.as_str() {
            if let Some(c) = normalize_cwe(s) {
                return Some(c);
            }
        }
        if let Some(n) = cwe.as_i64() {
            return Some(format!("CWE-{n}"));
        }
    }
    // relationships → taxa id like "CWE-79"
    if let Some(rels) = rule.get("relationships").and_then(|r| r.as_array()) {
        for rel in rels {
            if let Some(id) = rel
                .get("target")
                .and_then(|t| t.get("id"))
                .and_then(|i| i.as_str())
            {
                if id.to_ascii_uppercase().contains("CWE") {
                    if let Some(c) = normalize_cwe(id) {
                        return Some(c);
                    }
                }
            }
        }
    }
    None
}

pub fn parse(content: &str) -> AppResult<Vec<NewFinding>> {
    let doc: Value = serde_json::from_str(content)
        .map_err(|e| AppError::Import(format!("invalid SARIF JSON: {e}")))?;

    let runs = doc
        .get("runs")
        .and_then(|r| r.as_array())
        .ok_or_else(|| AppError::Import("SARIF document has no `runs` array".into()))?;

    let mut findings = Vec::new();

    for run in runs {
        // Build a ruleId → rule object map from the driver (and any extensions).
        let mut rules: HashMap<String, &Value> = HashMap::new();
        if let Some(tool) = run.get("tool") {
            let mut components = Vec::new();
            if let Some(driver) = tool.get("driver") {
                components.push(driver);
            }
            if let Some(exts) = tool.get("extensions").and_then(|e| e.as_array()) {
                components.extend(exts.iter());
            }
            for comp in components {
                if let Some(rule_arr) = comp.get("rules").and_then(|r| r.as_array()) {
                    for rule in rule_arr {
                        if let Some(id) = rule.get("id").and_then(|i| i.as_str()) {
                            rules.insert(id.to_string(), rule);
                        }
                    }
                }
            }
        }

        let results = match run.get("results").and_then(|r| r.as_array()) {
            Some(r) => r,
            None => continue,
        };

        for result in results {
            let rule_id = result
                .get("ruleId")
                .and_then(|r| r.as_str())
                .unwrap_or("")
                .to_string();

            let message = result
                .get("message")
                .and_then(|m| m.get("text"))
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();

            // Title: prefer rule name, else the rule id, else a trimmed message.
            let rule = rules.get(&rule_id).copied();
            let title = rule
                .and_then(|r| r.get("name").and_then(|n| n.as_str()))
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| (!rule_id.is_empty()).then(|| rule_id.clone()))
                .unwrap_or_else(|| first_line(&message, "SARIF result"));

            // Severity: explicit result.level, else rule defaultConfiguration.level.
            let level = result
                .get("level")
                .and_then(|l| l.as_str())
                .or_else(|| {
                    rule.and_then(|r| {
                        r.get("defaultConfiguration")
                            .and_then(|c| c.get("level"))
                            .and_then(|l| l.as_str())
                    })
                })
                .unwrap_or("warning");
            let severity = level_to_severity(level);

            let cwe = rule.and_then(rule_cwe);

            let evidence = first_location(result);

            findings.push(NewFinding {
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
                    summary: if message.is_empty() {
                        "Imported from SARIF report.".into()
                    } else {
                        message
                    },
                    ..Default::default()
                }),
                remediation: None,
                evidence,
                poc: None,
                refs: None,
                tags: Some(vec!["imported".into(), "sarif".into()]),
                retest_status: None,
                retest_date: None,
                custom_fields: None,
                mappings: None,
            });
        }
    }

    Ok(findings)
}

/// Extract file/line evidence from the first physical location of a result.
fn first_location(result: &Value) -> Option<Evidence> {
    let loc = result
        .get("locations")
        .and_then(|l| l.as_array())
        .and_then(|a| a.first())?;
    let phys = loc.get("physicalLocation")?;
    let file = phys
        .get("artifactLocation")
        .and_then(|a| a.get("uri"))
        .and_then(|u| u.as_str())
        .map(|s| s.to_string());
    let region = phys.get("region");
    let start_line = region
        .and_then(|r| r.get("startLine"))
        .and_then(|n| n.as_u64())
        .map(|n| n as u32);
    let end_line = region
        .and_then(|r| r.get("endLine"))
        .and_then(|n| n.as_u64())
        .map(|n| n as u32)
        .or(start_line);
    let snippet = region
        .and_then(|r| r.get("snippet"))
        .and_then(|s| s.get("text"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string());

    if file.is_none() && start_line.is_none() && snippet.is_none() {
        return None;
    }
    Some(Evidence {
        file,
        start_line,
        end_line,
        snippet,
    })
}

/// First non-empty line of `s`, or `fallback`.
fn first_line(s: &str, fallback: &str) -> String {
    s.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(|l| l.chars().take(200).collect())
        .unwrap_or_else(|| fallback.to_string())
}
