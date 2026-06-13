//! Burp Suite XML export importer (roxmltree).
//!
//! Maps `issues/issue`: `name` → title, `severity`
//! (High/Medium/Low/Information) → severity, `confidence`
//! (Certain/Firm/Tentative) → [`Confidence`], `issueBackground` →
//! description, `remediationBackground` → remediation, `host` + `path` →
//! evidence, and `vulnerabilityClassifications` (which embeds CWE links) → CWE.
//! Burp emits one `<issue>` per affected location; same-type issues are merged
//! so all affected URLs land on one finding. Burp wraps many text fields in
//! HTML and sometimes CDATA.

use std::collections::HashMap;

use roxmltree::{Document, Node};

use super::{annotate_cwe_name, normalize_cwe, severity_from_label, ImportOutcome};
use crate::error::{AppError, AppResult};
use crate::models::{
    Confidence, Evidence, FindingDescription, FindingKind, FindingRemediation, NewFinding,
};

/// Text content of the first direct child element named `tag`, trimmed and
/// HTML-stripped. Returns empty string if absent.
fn child_text(node: Node<'_, '_>, tag: &str) -> String {
    node.children()
        .find(|c| c.is_element() && c.has_tag_name(tag))
        .map(|c| strip_html(c.text().unwrap_or("")))
        .unwrap_or_default()
}

/// Naive HTML-tag stripper + entity decode for Burp's rich-text fields.
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
        .replace("&apos;", "'")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Map Burp's `confidence` label to our [`Confidence`]. Certain/Firm → High/
/// Medium, Tentative → Low; anything else → None (caller defaults).
fn confidence_from_label(label: &str) -> Option<Confidence> {
    match label.trim().to_ascii_lowercase().as_str() {
        "certain" => Some(Confidence::High),
        "firm" => Some(Confidence::Medium),
        "tentative" => Some(Confidence::Low),
        _ => None,
    }
}

/// Extract a CWE id from an `<issue>`. Burp records the weakness mapping inside
/// `<vulnerabilityClassifications>`, whose HTML body links to CWE entries like
/// `CWE-79: ...`. We scan the RAW (pre-strip) text for the first `CWE-<n>`.
fn issue_cwe(issue: Node<'_, '_>) -> Option<String> {
    let raw = issue
        .children()
        .find(|c| c.is_element() && c.has_tag_name("vulnerabilityClassifications"))
        .and_then(|c| c.text())?;
    // Find "CWE-" then read the trailing digits.
    let upper = raw.to_ascii_uppercase();
    let idx = upper.find("CWE-")?;
    let digits: String = upper[idx + 4..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        None
    } else {
        normalize_cwe(&digits)
    }
}

/// An accumulator merging same-type issues across their affected locations.
struct Acc {
    finding: NewFinding,
    locations: Vec<String>,
}

pub fn parse(content: &str) -> AppResult<ImportOutcome> {
    let doc =
        Document::parse(content).map_err(|e| AppError::Import(format!("invalid Burp XML: {e}")))?;

    let mut order: Vec<String> = Vec::new();
    let mut by_type: HashMap<String, Acc> = HashMap::new();

    for issue in doc
        .descendants()
        .filter(|n| n.is_element() && n.has_tag_name("issue"))
    {
        let title = {
            let t = child_text(issue, "name");
            if t.is_empty() {
                "Burp issue".to_string()
            } else {
                t
            }
        };

        // Merge key: prefer the stable serialNumber-independent `type` element.
        let key = {
            let ty = child_text(issue, "type");
            if ty.is_empty() {
                title.clone()
            } else {
                ty
            }
        };

        // host + path → location.
        let host = child_text(issue, "host");
        let path = child_text(issue, "path");
        let location = match (host.is_empty(), path.is_empty()) {
            (false, false) => format!("{host}{path}"),
            (false, true) => host,
            (true, false) => path,
            (true, true) => String::new(),
        };

        if let Some(acc) = by_type.get_mut(&key) {
            if !location.is_empty() && !acc.locations.contains(&location) {
                acc.locations.push(location);
            }
            continue;
        }

        let severity_label = child_text(issue, "severity");
        // Burp uses "Information" for info-level; severity_from_label handles it.
        let severity = severity_from_label(&severity_label);
        let confidence = confidence_from_label(&child_text(issue, "confidence"));

        let background = child_text(issue, "issueBackground");
        let detail = child_text(issue, "issueDetail");
        let summary = if !background.is_empty() {
            background
        } else if !detail.is_empty() {
            detail.clone()
        } else {
            "Imported from Burp Suite export.".to_string()
        };

        let remediation_text = {
            let bg = child_text(issue, "remediationBackground");
            let detail_rem = child_text(issue, "remediationDetail");
            match (bg.is_empty(), detail_rem.is_empty()) {
                (false, false) => format!("{bg}\n\n{detail_rem}"),
                (false, true) => bg,
                (true, false) => detail_rem,
                (true, true) => String::new(),
            }
        };

        let cwe = issue_cwe(issue);

        let finding = NewFinding {
            title,
            severity,
            confidence,
            // Burp is a dynamic web app scanner (DAST).
            kind: Some(FindingKind::Dast),
            cwe,
            cve: None,
            cvss_vector: None,
            cvss_score: None,
            triage_status: None,
            triage_note: None,
            description: Some(FindingDescription {
                summary,
                ..Default::default()
            }),
            remediation: Some(FindingRemediation {
                fix: remediation_text,
                code_patch: None,
                references: Vec::new(),
            }),
            evidence: Some(Evidence {
                file: None, // filled in at finalize from `locations`
                start_line: None,
                end_line: None,
                snippet: if detail.is_empty() {
                    None
                } else {
                    Some(detail)
                },
            }),
            poc: None,
            refs: None,
            tags: Some(vec!["imported".into(), "burp".into()]),
            retest_status: None,
            retest_date: None,
            custom_fields: None,
            mappings: None,
        };

        order.push(key.clone());
        by_type.insert(
            key,
            Acc {
                finding,
                locations: if location.is_empty() {
                    Vec::new()
                } else {
                    vec![location]
                },
            },
        );
    }

    let mut out = ImportOutcome::new();
    for key in order {
        let Acc {
            mut finding,
            locations,
        } = by_type.remove(&key).expect("key present");

        if let Some(ev) = finding.evidence.as_mut() {
            if let Some(first) = locations.first() {
                ev.file = Some(first.clone());
            }
            if locations.len() > 1 {
                let mut snippet = ev.snippet.clone().unwrap_or_default();
                if !snippet.is_empty() {
                    snippet.push_str("\n\n");
                }
                snippet.push_str(&format!(
                    "Affected URLs ({}):\n{}",
                    locations.len(),
                    locations.join("\n")
                ));
                ev.snippet = Some(snippet);
            }
            if ev.file.is_none() && ev.snippet.is_none() {
                finding.evidence = None;
            }
        }
        annotate_cwe_name(&mut finding);
        out.push(finding);
    }

    Ok(out)
}
