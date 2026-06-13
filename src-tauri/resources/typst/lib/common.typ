// Shared helpers for pwn2report themes: severity color/label, badges,
// section headers, and the page header/footer. Kept robust to empty strings
// (the Rust render IR flattens all optional fields to "" / empty arrays).

// own2pwn severity palette.
#let severity-color(sev) = {
  if sev == "critical" { rgb("#dc2626") }
  else if sev == "high" { rgb("#ea580c") }
  else if sev == "medium" { rgb("#d97706") }
  else if sev == "low" { rgb("#2563eb") }
  else { rgb("#6b7280") } // info / unknown
}

// own2pwn accent violet.
#let accent = rgb("#7c5cff")

#let severity-label(sev) = upper(sev)

// A colored, rounded severity pill.
#let severity-badge(sev) = {
  box(
    fill: severity-color(sev),
    inset: (x: 8pt, y: 3pt),
    radius: 4pt,
    text(fill: white, weight: "bold", size: 8pt, severity-label(sev)),
  )
}

// A neutral small pill (for kind/confidence/tags).
#let tag-pill(label) = {
  box(
    fill: luma(235),
    inset: (x: 6pt, y: 2pt),
    radius: 3pt,
    text(size: 8pt, fill: luma(60), label),
  )
}

// Evaluate a prose VALUE as Typst markup. The Rust PDF path pre-converts these
// prose fields from Markdown to compile-safe Typst markup (render/markup.rs), so
// here we `eval` them in markup mode to get formatted output (bold, lists,
// links, code, …). Robust to empty / non-string values: empty strings render
// nothing, and a non-string (defensive) falls back to plain display.
#let prose(body) = {
  if body == none { return }
  if type(body) == str {
    if body != "" { eval(body, mode: "markup") }
  } else {
    body
  }
}

// Render a labelled facet block only when the body is non-empty. The body is a
// prose VALUE (Typst markup produced by the Rust converter) and is `eval`'d.
#let facet(title, body) = {
  if body != none and body != "" {
    block(spacing: 6pt, text(weight: "semibold", size: 10pt, fill: accent, title))
    block(spacing: 10pt, prose(body))
  }
}

// A monospace code block (used for snippets, payloads, patches).
#let code-block(body) = {
  if body != none and body != "" {
    block(
      width: 100%,
      fill: luma(245),
      stroke: 0.5pt + luma(210),
      inset: 8pt,
      radius: 4pt,
      text(font: "JetBrains Mono", size: 8.5pt, raw(body)),
    )
  }
}

// Running page header/footer applied via `set page(...)` in the theme.
#let make-header(doc) = context {
  if counter(page).get().first() > 1 {
    set text(size: 8pt, fill: luma(140))
    grid(
      columns: (1fr, auto),
      align: (left, right),
      doc.title,
      doc.client,
    )
    line(length: 100%, stroke: 0.5pt + luma(220))
  }
}

#let make-footer() = context {
  set text(size: 8pt, fill: luma(140))
  set align(center)
  [#counter(page).display("1 / 1", both: true)]
}

// ---------------------------------------------------------------------------
// Shared page-level blocks used by every theme (web_pentest / code_audit /
// red_team). Each takes the render-IR `doc` (or a finding `f`) and is robust to
// empty strings / empty arrays.
// ---------------------------------------------------------------------------

// Centered title page: report-type, title, client, date, status.
#let title-page(doc) = page(header: none, footer: none, {
  set align(center + horizon)
  block({
    text(size: 12pt, fill: accent, weight: "bold", upper(doc.report_type))
    v(1.2em)
    text(size: 30pt, weight: "bold", doc.title)
    v(0.6em)
    line(length: 40%, stroke: 1pt + accent)
    v(0.6em)
    if doc.client != "" {
      text(size: 16pt, fill: luma(80), doc.client)
      v(0.4em)
    }
    text(size: 11pt, fill: luma(120), doc.date)
    if doc.status != "" {
      v(0.3em)
      text(size: 9pt, fill: luma(150), upper(doc.status))
    }
  })
})

// The per-severity summary table (counts + total).
#let severity-summary-table(summary) = {
  let count-cell(sev, n) = (
    severity-badge(sev),
    align(center, text(weight: "bold", str(n))),
  )
  table(
    columns: (auto, auto, auto, auto, auto, auto),
    align: (horizon, horizon, horizon, horizon, horizon, horizon),
    stroke: 0.5pt + luma(220),
    inset: 8pt,
    ..count-cell("critical", summary.critical),
    ..count-cell("high", summary.high),
    ..count-cell("medium", summary.medium),
    ..count-cell("low", summary.low),
    ..count-cell("info", summary.info),
    table.cell(fill: luma(245), text(weight: "bold", "TOTAL")),
    align(center, text(weight: "bold", str(summary.total))),
  )
}

// A finding's heading line: severity badge + numbered title.
#let finding-heading(n, f) = block(spacing: 8pt, {
  grid(
    columns: (auto, 1fr),
    column-gutter: 10pt,
    align: (horizon, horizon),
    severity-badge(f.severity),
    text(size: 13pt, weight: "bold", [#(n). #f.title]),
  )
})

// A finding's meta line (CWE / CVE / CVSS / confidence / kind) + CVSS vector.
#let finding-meta(f) = {
  let meta = ()
  if f.cwe != "" { meta.push(f.cwe) }
  if f.cve != "" { meta.push(f.cve) }
  if f.cvss_score != "" { meta.push("CVSS " + f.cvss_score) }
  if f.confidence != "" { meta.push("confidence: " + f.confidence) }
  if f.kind != "" { meta.push(f.kind) }
  if meta.len() > 0 {
    block(spacing: 6pt, text(size: 8.5pt, fill: luma(120), meta.join("  ·  ")))
  }
  if f.cvss_vector != "" {
    block(spacing: 8pt, text(size: 8pt, fill: luma(140), font: "JetBrains Mono", f.cvss_vector))
  }
}

// Evidence location string ("file:lines" / "file" / "").
#let evidence-loc(f) = {
  if f.evidence_file != "" {
    if f.evidence_lines != "" { f.evidence_file + ":" + f.evidence_lines } else { f.evidence_file }
  } else { "" }
}

// A reference list block (only when refs is non-empty).
#let references-block(refs) = {
  if refs.len() > 0 {
    block(spacing: 6pt, {
      text(size: 9pt, weight: "semibold", "References")
      list(..refs.map(r => text(size: 9pt, link(r))))
    })
  }
}

// Evidence images for a finding. Each image is its raw bytes (PNG/JPG/…) from
// the render IR (`f.images`), rendered as a captioned figure. No-ops when the
// finding has no images. Width is capped so large screenshots stay on the page.
#let finding-images(f) = {
  if "images" in f and f.images.len() > 0 {
    block(spacing: 6pt, text(weight: "semibold", size: 10pt, fill: accent, "Screenshots"))
    for img in f.images {
      block(spacing: 8pt, {
        figure(
          image(img.data, width: 85%),
          caption: if img.caption != "" { img.caption } else { none },
        )
      })
    }
  }
}

// A horizontal separator between findings (skips the last).
#let finding-separator(i, total) = {
  if i + 1 < total {
    v(0.4em)
    line(length: 100%, stroke: 0.5pt + luma(225))
    v(0.4em)
  }
}
