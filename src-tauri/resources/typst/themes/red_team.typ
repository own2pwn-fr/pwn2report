// pwn2report — A4 red-team report theme.
//
// Reads its data from `#import sys: inputs` (populated by the Rust render IR in
// render/content_model.rs). Shares the title page / severity-summary table /
// header-footer with the other themes (via lib/common.typ), but each finding
// reads like an ATTACK STORY: the PoC scenario leads, the exploitation steps are
// a numbered narrative, the payload is shown, and severity is still surfaced.
//
// CUSTOM TEMPLATES: bundled default for the `red_team` report type. A user
// override lives at `<app_config_dir>/templates/red_team.typ`. A custom
// template MUST import the shared lib at the stable path below — do NOT change
// it (it is registered in-memory by the renderer under exactly this path):
//   #import "lib/common.typ": ...
//
// Robust to missing optional fields: the IR flattens them to "" / empty arrays.

#import sys: inputs
#import "lib/common.typ": severity-color, severity-label, severity-badge, tag-pill, facet, code-block, accent, make-header, make-footer, title-page, severity-summary-table, finding-heading, finding-meta, evidence-loc, references-block, finding-separator

#let doc = inputs

// ---------------------------------------------------------------------------
// Page + text defaults
// ---------------------------------------------------------------------------
#set page(
  paper: "a4",
  margin: (x: 2.2cm, y: 2.4cm),
  header: make-header(doc),
  footer: make-footer(),
)
#set text(font: "Inter", size: 10.5pt, lang: "en")
#set par(justify: true, leading: 0.62em)
#show heading: set text(fill: accent)
#set heading(numbering: none)

// ---------------------------------------------------------------------------
// Title page
// ---------------------------------------------------------------------------
#title-page(doc)

#pagebreak()

// ---------------------------------------------------------------------------
// Executive summary (the engagement narrative overview)
// ---------------------------------------------------------------------------
#if doc.exec_summary != "" {
  heading(level: 1, "Engagement Summary")
  block(doc.exec_summary)
  v(0.5em)
}

// ---------------------------------------------------------------------------
// Severity summary table
// ---------------------------------------------------------------------------
#heading(level: 1, "Impact Overview")
#severity-summary-table(doc.summary)
#v(0.5em)

// ---------------------------------------------------------------------------
// Scope (rules of engagement) & methodology (attack approach)
// ---------------------------------------------------------------------------
#if doc.scope != "" {
  heading(level: 1, "Rules of Engagement")
  block(doc.scope)
}
#if doc.methodology != "" {
  heading(level: 1, "Approach")
  block(doc.methodology)
}

// ---------------------------------------------------------------------------
// Findings — attack-narrative layout
// ---------------------------------------------------------------------------
#if doc.findings.len() > 0 {
  pagebreak()
  heading(level: 1, "Attack Narratives")

  for (i, f) in doc.findings.enumerate() {
    finding-heading(i + 1, f)
    finding-meta(f)

    // Lead with the scenario — the story of the attack.
    if f.has_poc and f.poc_scenario != "" {
      facet("Scenario", f.poc_scenario)
    } else if f.summary != "" {
      facet("Scenario", f.summary)
    }

    // Numbered exploitation walk-through.
    if f.has_poc and f.poc_steps.len() > 0 {
      block(spacing: 6pt, text(weight: "semibold", size: 10pt, fill: accent, "Exploitation steps"))
      block(spacing: 6pt, enum(..f.poc_steps))
    }

    // Payload used in the exploitation.
    if f.has_poc and f.poc_payload != "" {
      block(spacing: 6pt, text(weight: "semibold", size: 10pt, fill: accent, "Payload"))
      code-block(f.poc_payload)
    }

    // Supporting context — attack vector and business impact tell the "so what".
    facet("Attack vector", f.attack_vector)
    facet("Business impact", f.business_impact)
    facet("Technical details", f.technical_details)
    facet("Root cause", f.root_cause)

    // Evidence captured during the operation.
    if f.has_evidence {
      let loc = evidence-loc(f)
      block(spacing: 6pt, text(weight: "semibold", size: 10pt, fill: accent, "Evidence"))
      if loc != "" {
        block(spacing: 4pt, text(size: 8.5pt, fill: luma(120), font: "JetBrains Mono", loc))
      }
      code-block(f.evidence_snippet)
    }

    // Remediation / hardening recommendations.
    if f.fix != "" or f.code_patch != "" or f.remediation_refs.len() > 0 {
      facet("Recommendation", f.fix)
      code-block(f.code_patch)
      references-block(f.remediation_refs)
    }

    // Tags.
    if f.tags.len() > 0 {
      block(spacing: 8pt, f.tags.map(tag-pill).join(h(4pt)))
    }

    finding-separator(i, doc.findings.len())
  }
} else {
  v(1em)
  text(fill: luma(130), style: "italic", "No findings recorded for this report.")
}
