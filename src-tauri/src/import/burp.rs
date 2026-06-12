//! Burp Suite XML export importer (roxmltree).
//!
//! Maps `issues/issue`: `name` → title, `severity`
//! (High/Medium/Low/Information) → severity, `issueBackground` →
//! description, `remediationBackground` → remediation, `host` + `path` →
//! evidence. Burp wraps many text fields in HTML and sometimes CDATA.

use roxmltree::{Document, Node};

use super::severity_from_label;
use crate::error::{AppError, AppResult};
use crate::models::{Evidence, FindingDescription, FindingKind, FindingRemediation, NewFinding};

/// Text content of the first direct child element named `tag`, trimmed and
/// HTML-stripped. Returns empty string if absent.
fn child_text(node: Node<'_, '_>, tag: &str) -> String {
    node.children()
        .find(|c| c.is_element() && c.has_tag_name(tag))
        .map(|c| strip_html(&c.text().unwrap_or("").to_string()))
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

pub fn parse(content: &str) -> AppResult<Vec<NewFinding>> {
    let doc = Document::parse(content)
        .map_err(|e| AppError::Import(format!("invalid Burp XML: {e}")))?;

    let mut findings = Vec::new();

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

        let severity_label = child_text(issue, "severity");
        // Burp uses "Information" for info-level; severity_from_label handles it.
        let severity = severity_from_label(&severity_label);

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

        // host + path → evidence file (URL).
        let host = child_text(issue, "host");
        let path = child_text(issue, "path");
        let location = match (host.is_empty(), path.is_empty()) {
            (false, false) => format!("{host}{path}"),
            (false, true) => host,
            (true, false) => path,
            (true, true) => String::new(),
        };
        let evidence = if location.is_empty() {
            None
        } else {
            Some(Evidence {
                file: Some(location),
                start_line: None,
                end_line: None,
                snippet: if detail.is_empty() { None } else { Some(detail) },
            })
        };

        findings.push(NewFinding {
            title,
            severity,
            confidence: None,
            kind: Some(FindingKind::Sast),
            cwe: None,
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
            evidence,
            poc: None,
            refs: None,
            tags: Some(vec!["imported".into(), "burp".into()]),
        });
    }

    Ok(findings)
}
