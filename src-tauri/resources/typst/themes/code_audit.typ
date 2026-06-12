// pwn2report — A4 code-audit report theme.
//
// Reads its data from `#import sys: inputs` (populated by the Rust render IR in
// render/content_model.rs). Shares the title page / severity-summary table /
// header-footer with the other themes (via lib/common.typ), but per finding it
// emphasises the SOURCE: file/line location first, the evidence code snippet in
// a JetBrains Mono block, the CWE, and the remediation code patch as a code
// block.
//
// CUSTOM TEMPLATES: bundled default for the `code_audit` report type. A user
// override lives at `<app_config_dir>/templates/code_audit.typ`. A custom
// template MUST import the shared lib at the stable path below — do NOT change
// it (it is registered in-memory by the renderer under exactly this path):
//   #import "lib/common.typ": ...
//
// Robust to missing optional fields: the IR flattens them to "" / empty arrays.

#import sys: inputs
#import "lib/common.typ": severity-color, severity-label, severity-badge, tag-pill, facet, code-block, accent, make-header, make-footer, title-page, severity-summary-table, finding-heading, finding-meta, evidence-loc, references-block, finding-separator, finding-images

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

// A prominent location banner ("file:lines"), monospace.
#let location-banner(f) = {
  let loc = evidence-loc(f)
  if loc != "" {
    block(
      width: 100%,
      fill: rgb("#f3f0ff"),
      stroke: 0.5pt + accent,
      inset: 6pt,
      radius: 4pt,
      text(font: "JetBrains Mono", size: 9pt, fill: accent, weight: "bold", loc),
    )
  }
}

// ---------------------------------------------------------------------------
// Title page
// ---------------------------------------------------------------------------
#title-page(doc)

#pagebreak()

// ---------------------------------------------------------------------------
// Executive summary
// ---------------------------------------------------------------------------
#if doc.exec_summary != "" {
  heading(level: 1, "Executive Summary")
  block(doc.exec_summary)
  v(0.5em)
}

// ---------------------------------------------------------------------------
// Severity summary table
// ---------------------------------------------------------------------------
#heading(level: 1, "Findings Overview")
#severity-summary-table(doc.summary)
#v(0.5em)

// ---------------------------------------------------------------------------
// Scope & methodology
// ---------------------------------------------------------------------------
#if doc.scope != "" {
  heading(level: 1, "Scope")
  block(doc.scope)
}
#if doc.methodology != "" {
  heading(level: 1, "Methodology")
  block(doc.methodology)
}

// ---------------------------------------------------------------------------
// Findings — source-centric layout
// ---------------------------------------------------------------------------
#if doc.findings.len() > 0 {
  pagebreak()
  heading(level: 1, "Detailed Findings")

  for (i, f) in doc.findings.enumerate() {
    finding-heading(i + 1, f)

    // Location banner first — code audits lead with where the issue lives.
    location-banner(f)

    // CWE called out explicitly (in addition to the meta line).
    if f.cwe != "" {
      block(spacing: 6pt, text(size: 9pt, weight: "semibold", fill: accent, "Weakness: " + f.cwe))
    }
    finding-meta(f)

    // The vulnerable code snippet, prominent.
    if f.evidence_snippet != "" {
      block(spacing: 6pt, text(weight: "semibold", size: 10pt, fill: accent, "Vulnerable code"))
      code-block(f.evidence_snippet)
    }

    // Description facets — technical first for an audit audience.
    facet("Summary", f.summary)
    facet("Root cause", f.root_cause)
    facet("Technical details", f.technical_details)
    facet("Attack vector", f.attack_vector)
    facet("Business impact", f.business_impact)

    // Proof of Concept (optional, secondary in an audit).
    if f.has_poc {
      block(spacing: 6pt, text(weight: "semibold", size: 10pt, fill: accent, "Proof of Concept"))
      if f.poc_scenario != "" { block(spacing: 6pt, f.poc_scenario) }
      if f.poc_steps.len() > 0 {
        block(spacing: 6pt, enum(..f.poc_steps))
      }
      code-block(f.poc_payload)
    }

    // Evidence images (screenshots / diagrams).
    finding-images(f)

    // Remediation — the fix description plus the suggested code patch.
    if f.fix != "" or f.code_patch != "" or f.remediation_refs.len() > 0 {
      facet("Remediation", f.fix)
      if f.code_patch != "" {
        block(spacing: 6pt, text(size: 9pt, weight: "semibold", fill: accent, "Suggested patch"))
        code-block(f.code_patch)
      }
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
