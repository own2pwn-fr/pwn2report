//! Minimal CVSS v3.x / v4.0 vector decoder.
//!
//! Turns a raw CVSS vector string (e.g.
//! `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) into a list of
//! `(localized metric label, localized metric value)` pairs so the renderers can
//! show a human-readable grid instead of the opaque vector. Only the *base*
//! metrics are decoded (the ones that matter for a report's at-a-glance grid);
//! temporal / environmental / threat / supplemental metrics are ignored.
//!
//! All visible strings come from [`Labels`] (localized) — the decoder never
//! emits English literals. Unknown metric keys or values are skipped, so a
//! malformed or partial vector degrades to whatever it can decode (possibly an
//! empty list, in which case the caller falls back to the raw vector string).

use super::labels::Labels;

/// One decoded CVSS metric: a localized `(label, value)` pair.
pub type CvssMetric = (&'static str, &'static str);

/// Decode the base metrics of a CVSS v3.x / v4.0 vector into localized
/// `(label, value)` pairs, in canonical display order. Returns an empty vec when
/// nothing recognizable was decoded (caller should then show the raw vector).
///
/// The version prefix (`CVSS:3.1` / `CVSS:4.0`) is tolerated but not required;
/// metrics are matched by their key regardless. v4.0's `AT` (Attack
/// Requirements) and v3.x's `S` (Scope) coexist — both are decoded when present.
pub fn decode(vector: &str, l: &Labels) -> Vec<CvssMetric> {
    // Parse "KEY:VAL" tokens into a lookup, skipping the version prefix.
    let mut metrics: Vec<(&str, &str)> = Vec::new();
    for token in vector.split('/') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        // Split on the FIRST ':' only (the version token is "CVSS:3.1").
        if let Some((key, val)) = token.split_once(':') {
            if key.eq_ignore_ascii_case("CVSS") {
                continue; // version prefix, not a metric
            }
            metrics.push((key, val));
        }
    }

    // Canonical display order of base metrics. v3 uses PR/UI/S; v4 uses AT and
    // drops S. We list every base key once; absent keys are simply skipped.
    let order: &[&str] = &["AV", "AC", "AT", "PR", "UI", "S", "C", "I", "A"];

    let mut out: Vec<CvssMetric> = Vec::new();
    for &key in order {
        if let Some(&(_, val)) = metrics.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)) {
            if let (Some(label), Some(value)) = (metric_label(key, l), metric_value(key, val, l)) {
                out.push((label, value));
            }
        }
    }
    out
}

/// Localized name for a base-metric key (`None` for unrecognized keys).
fn metric_label(key: &str, l: &Labels) -> Option<&'static str> {
    Some(match key.to_ascii_uppercase().as_str() {
        "AV" => l.cvss_attack_vector,
        "AC" => l.cvss_attack_complexity,
        "AT" => l.cvss_attack_requirements,
        "PR" => l.cvss_privileges_required,
        "UI" => l.cvss_user_interaction,
        "S" => l.cvss_scope,
        "C" => l.cvss_confidentiality,
        "I" => l.cvss_integrity,
        "A" => l.cvss_availability,
        _ => return None,
    })
}

/// Localized value for a base metric (`None` for unrecognized key/value pairs).
fn metric_value(key: &str, val: &str, l: &Labels) -> Option<&'static str> {
    let key = key.to_ascii_uppercase();
    let val = val.to_ascii_uppercase();
    Some(match (key.as_str(), val.as_str()) {
        // Attack Vector.
        ("AV", "N") => l.cvss_network,
        ("AV", "A") => l.cvss_adjacent,
        ("AV", "L") => l.cvss_local,
        ("AV", "P") => l.cvss_physical,
        // Attack Complexity.
        ("AC", "L") => l.cvss_low,
        ("AC", "H") => l.cvss_high,
        // Attack Requirements (v4.0).
        ("AT", "N") => l.cvss_none,
        ("AT", "P") => l.cvss_present,
        // Privileges Required.
        ("PR", "N") => l.cvss_none,
        ("PR", "L") => l.cvss_low,
        ("PR", "H") => l.cvss_high,
        // User Interaction. v3: N/R. v4: N/P (passive) / A (active).
        ("UI", "N") => l.cvss_none,
        ("UI", "R") => l.cvss_required,
        ("UI", "P") => l.cvss_passive,
        ("UI", "A") => l.cvss_active,
        // Scope (v3 only).
        ("S", "U") => l.cvss_unchanged,
        ("S", "C") => l.cvss_changed,
        // Confidentiality / Integrity / Availability (same scale).
        ("C" | "I" | "A", "N") => l.cvss_none,
        ("C" | "I" | "A", "L") => l.cvss_low,
        ("C" | "I" | "A", "H") => l.cvss_high,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_v31_base_vector_in_order() {
        let l = Labels::for_lang("en");
        let m = decode("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", &l);
        assert_eq!(
            m,
            vec![
                ("Attack vector", "Network"),
                ("Attack complexity", "Low"),
                ("Privileges required", "None"),
                ("User interaction", "None"),
                ("Scope", "Unchanged"),
                ("Confidentiality", "High"),
                ("Integrity", "High"),
                ("Availability", "High"),
            ]
        );
    }

    #[test]
    fn decodes_v40_attack_requirements_and_passive_ui() {
        let l = Labels::for_lang("en");
        let m = decode("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H", &l);
        // AT and the passive UI are decoded; the V-prefixed v4 impact metrics are
        // ignored (only the shared base keys are surfaced).
        assert!(m.contains(&("Attack requirements", "Present")));
        assert!(m.contains(&("User interaction", "Passive")));
        assert!(m.contains(&("Attack vector", "Network")));
    }

    #[test]
    fn localizes_to_french() {
        let l = Labels::for_lang("fr");
        let m = decode("CVSS:3.1/AV:N/C:H", &l);
        assert_eq!(m[0], ("Vecteur d'attaque", "Réseau"));
        assert_eq!(m[1], ("Confidentialité", "Élevée"));
    }

    #[test]
    fn empty_or_garbage_yields_empty() {
        let l = Labels::for_lang("en");
        assert!(decode("", &l).is_empty());
        assert!(decode("not-a-vector", &l).is_empty());
        // Unknown values are skipped rather than emitted.
        assert!(decode("CVSS:3.1/AV:Z", &l).is_empty());
    }

    #[test]
    fn no_version_prefix_still_decodes() {
        let l = Labels::for_lang("en");
        let m = decode("AV:L/AC:H", &l);
        assert_eq!(
            m,
            vec![("Attack vector", "Local"), ("Attack complexity", "High")]
        );
    }
}
