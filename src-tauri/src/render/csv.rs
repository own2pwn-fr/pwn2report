//! CSV exporter — one row per finding.
//!
//! A pure projection of the [`ReportDocument`] IR to a CSV string (RFC 4180
//! quoting). Columns: id, title, severity, cvss, cwe, cve, status, retest,
//! affected_assets. `id` is the 1-based finding index (the IR carries no DB id),
//! kept so rows are stably referenceable.

use super::content_model::{FindingInput, ReportDocument};

/// Render every finding of the report as a CSV document (header + one row each).
pub fn to_csv(doc: &ReportDocument) -> String {
    let mut out = String::new();
    out.push_str("id,title,severity,cvss,cwe,cve,status,retest,affected_assets\n");
    for (i, f) in doc.findings.iter().enumerate() {
        push_row(&mut out, i + 1, f);
    }
    out
}

fn push_row(out: &mut String, id: usize, f: &FindingInput) {
    let assets = f
        .affected_assets
        .iter()
        .map(|a| a.identifier.as_str())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    let retest = if f.has_retest {
        f.retest_status_label.as_str()
    } else {
        ""
    };
    let cols = [
        id.to_string(),
        f.title.clone(),
        f.severity.clone(),
        f.cvss_score.clone(),
        f.cwe.clone(),
        f.cve.clone(),
        f.triage_status.clone(),
        retest.to_string(),
        assets,
    ];
    let line: Vec<String> = cols.iter().map(|c| quote(c)).collect();
    out.push_str(&line.join(","));
    out.push('\n');
}

/// RFC 4180 field quoting: wrap in double quotes and double any embedded quote
/// when the field contains a comma, quote, CR or LF.
fn quote(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::to_csv;
    use crate::render::content_model::build_document;
    use crate::test_fixtures::{sample_finding, sample_report};

    #[test]
    fn csv_has_header_and_one_row_per_finding() {
        let doc = build_document(
            &sample_report(),
            vec![sample_finding()],
            &HashMap::new(),
            &[],
            &HashMap::new(),
            None,
        );
        let csv = to_csv(&doc);
        let mut lines = csv.lines();
        assert_eq!(
            lines.next().unwrap(),
            "id,title,severity,cvss,cwe,cve,status,retest,affected_assets"
        );
        let row = lines.next().expect("one data row");
        assert!(row.starts_with("1,SQL Injection,high,"));
        assert!(row.contains("CWE-89"));
        assert!(lines.next().is_none(), "exactly one finding row");
    }

    #[test]
    fn csv_quotes_fields_with_commas_and_quotes() {
        let mut f = sample_finding();
        f.title = "Bad, \"quoted\" title".into();
        let doc = build_document(
            &sample_report(),
            vec![f],
            &HashMap::new(),
            &[],
            &HashMap::new(),
            None,
        );
        let csv = to_csv(&doc);
        assert!(csv.contains("\"Bad, \"\"quoted\"\" title\""));
    }
}
