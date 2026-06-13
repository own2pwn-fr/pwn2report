//! SARIF 2.1.0 exporter.
//!
//! A pure projection of the [`ReportDocument`] IR to a minimal but valid SARIF
//! 2.1.0 document: one `run` whose `results` mirror the report's findings
//! (`ruleId` = CWE, `level` from severity, `locations` from the evidence file/
//! line). Built with `serde_json` so quoting/escaping is always correct.

use serde_json::{json, Value};

use super::content_model::{FindingInput, ReportDocument};

/// SARIF `level` for a snake_case severity string. SARIF only defines
/// error/warning/note/none; critical+high → error, medium → warning, low →
/// note, info → none.
fn severity_to_level(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "error",
        "medium" => "warning",
        "low" => "note",
        _ => "none",
    }
}

/// Render the report as a SARIF 2.1.0 JSON string (pretty-printed).
pub fn to_sarif(doc: &ReportDocument) -> String {
    // Collect distinct rules (by ruleId) so the driver advertises them.
    let mut rules: Vec<Value> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for f in &doc.findings {
        let rule_id = rule_id(f);
        if seen.iter().any(|s| s == &rule_id) {
            continue;
        }
        seen.push(rule_id.clone());
        let mut rule = json!({ "id": rule_id, "name": f.title });
        if !f.cwe.is_empty() {
            rule["properties"] = json!({ "cwe": f.cwe });
        }
        rules.push(rule);
    }

    let results: Vec<Value> = doc.findings.iter().map(result_for).collect();

    let sarif = json!({
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "pwn2report",
                    "informationUri": "https://github.com/own2pwn/pwn2report",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
}

/// The SARIF `ruleId` for a finding: its CWE when present, else a slugged title.
fn rule_id(f: &FindingInput) -> String {
    if !f.cwe.is_empty() {
        f.cwe.clone()
    } else {
        let slug: String = f
            .title
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        format!("p2r-{}", slug.trim_matches('-').to_ascii_lowercase())
    }
}

fn result_for(f: &FindingInput) -> Value {
    let mut result = json!({
        "ruleId": rule_id(f),
        "level": severity_to_level(&f.severity),
        "message": { "text": message_text(f) },
    });

    if !f.evidence_file.is_empty() {
        let mut phys = json!({
            "artifactLocation": { "uri": f.evidence_file }
        });
        // Parse "start" or "start-end" back into a region when present.
        if let Some((start, end)) = parse_lines(&f.evidence_lines) {
            let mut region = json!({ "startLine": start });
            if let Some(e) = end {
                region["endLine"] = json!(e);
            }
            phys["region"] = region;
        }
        result["locations"] = json!([{ "physicalLocation": phys }]);
    }

    // Carry the numeric CVSS score through the SARIF security-severity property.
    if !f.cvss_score.is_empty() {
        result["properties"] = json!({ "security-severity": f.cvss_score });
    }

    result
}

/// The result message: the finding summary, falling back to the title.
fn message_text(f: &FindingInput) -> String {
    if f.summary.trim().is_empty() {
        f.title.clone()
    } else {
        f.summary.clone()
    }
}

/// Parse the IR's `evidence_lines` ("12" or "12-20") into `(start, end?)`.
fn parse_lines(s: &str) -> Option<(u32, Option<u32>)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    match s.split_once('-') {
        Some((a, b)) => {
            let start = a.trim().parse::<u32>().ok()?;
            let end = b.trim().parse::<u32>().ok();
            Some((start, end))
        }
        None => Some((s.parse::<u32>().ok()?, None)),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::to_sarif;
    use crate::render::content_model::build_document;
    use crate::test_fixtures::{sample_finding, sample_report};

    #[test]
    fn sarif_export_is_valid_2_1_0_with_results() {
        let doc = build_document(
            &sample_report(),
            vec![sample_finding()],
            HashMap::new(),
            &[],
            &HashMap::new(),
            None,
        );
        let s = to_sarif(&doc);
        let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
        assert_eq!(v["version"], "2.1.0");
        let results = v["runs"][0]["results"].as_array().expect("results array");
        assert_eq!(results.len(), 1);
        // CWE-89 finding → ruleId is the CWE, level error (high severity).
        assert_eq!(results[0]["ruleId"], "CWE-89");
        assert_eq!(results[0]["level"], "error");
        // Evidence file → physical location.
        let uri = &results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"];
        assert!(uri.is_string());
        // Driver advertises the rule.
        let rules = v["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules array");
        assert!(rules.iter().any(|r| r["id"] == "CWE-89"));
    }

    #[test]
    fn sarif_level_maps_from_severity() {
        use super::severity_to_level;
        assert_eq!(severity_to_level("critical"), "error");
        assert_eq!(severity_to_level("high"), "error");
        assert_eq!(severity_to_level("medium"), "warning");
        assert_eq!(severity_to_level("low"), "note");
        assert_eq!(severity_to_level("info"), "none");
    }
}
