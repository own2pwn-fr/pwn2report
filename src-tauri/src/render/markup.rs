//! Markdown → Typst-markup converter for the PDF path.
//!
//! Prose fields (report exec_summary/scope/methodology, finding description
//! facets, remediation fix) are authored as Markdown. The Markdown / HTML /
//! DOCX renderers consume that raw text directly. The **Typst** path, however,
//! injects prose into the template where it is `eval`'d as Typst markup — so it
//! must first be translated into *valid, compile-safe* Typst markup.
//!
//! Security / robustness is the whole point of this module: a finding's prose is
//! attacker-influenceable (it can come from imported scan output), and a single
//! stray `#`, `$`, backtick, `@` or `\` would otherwise break — or worse,
//! inject into — the Typst compilation. The strategy is therefore:
//!
//!   * every text run is emitted through [`escape_text`], which backslash-
//!     escapes **all** Typst-special characters so the run renders literally and
//!     can never be reinterpreted as markup;
//!   * Typst constructs are emitted **only** for Markdown we explicitly
//!     recognize (headings, bold, italic, code, lists, links, code fences);
//!   * anything unrecognized degrades to escaped plain text.
//!
//! Supported Markdown subset:
//!   * ATX headings `#`..`######` → bold text (capped so prose never outranks
//!     the section titles the theme owns);
//!   * `**bold**` / `__bold__` → `*bold*`;
//!   * `*italic*` / `_italic_` → `_italic_`;
//!   * inline `` `code` `` → Typst `raw`;
//!   * fenced ```` ```lang … ``` ```` → Typst raw block with language;
//!   * unordered lists (`- ` / `* ` / `+ `) → `- `;
//!   * ordered lists (`1.`) → `+ `;
//!   * links `[text](url)` → `#link("url")[text]`;
//!   * paragraphs (blank line) and hard line breaks (trailing two spaces or a
//!     lone newline inside a paragraph).
//!
//! The output is a Typst-markup string intended to be `eval`'d with
//! `mode: "markup"`.

/// Characters that carry syntactic meaning in Typst markup mode and so MUST be
/// backslash-escaped when they appear in a literal text run. Backslash itself is
/// first in the list so the replace pass escapes it before introducing new
/// backslashes for the others.
const TYPST_SPECIAL: &[char] = &[
    '\\', '#', '$', '*', '_', '`', '<', '>', '@', '[', ']', '=', '-', '+', '/', '~', '"', '\'',
];

/// Escape every Typst-special character in a literal text run so it renders
/// verbatim and can never be reinterpreted as Typst markup.
///
/// This is intentionally aggressive: over-escaping is harmless (Typst renders
/// `\#` as a literal `#`), whereas under-escaping risks broken or injected
/// compilation. Newlines are preserved as-is (paragraph/line-break handling is
/// done by the caller).
pub fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + s.len() / 8);
    for c in s.chars() {
        if TYPST_SPECIAL.contains(&c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Escape a string for use inside a Typst double-quoted string literal (the URL
/// of a `#link("…")`). Only the backslash and the double quote are significant
/// there.
fn escape_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Convert a safe subset of Markdown into valid, compile-safe Typst markup.
///
/// See the module docs for the supported subset and the escaping strategy.
/// Returns an empty string for empty / whitespace-only input.
pub fn md_to_typst(md: &str) -> String {
    if md.trim().is_empty() {
        return String::new();
    }

    let lines: Vec<&str> = md.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    // Whether the previous emitted block needs a paragraph separator before the
    // next one. Set after we emit a block; reset by blank lines.
    let mut need_para_break = false;

    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();

        // Blank line → paragraph boundary.
        if trimmed.trim().is_empty() {
            if need_para_break {
                out.push_str("\n\n");
                need_para_break = false;
            }
            i += 1;
            continue;
        }

        // Fenced code block: ``` or ~~~ (optionally with an info string).
        if let Some(fence) = code_fence(trimmed) {
            if need_para_break {
                out.push_str("\n\n");
            }
            let (block, next) = collect_code_fence(&lines, i, fence);
            out.push_str(&block);
            i = next;
            need_para_break = true;
            continue;
        }

        // ATX heading: 1–6 leading '#', a space, then text.
        if let Some((_level, text)) = atx_heading(trimmed) {
            if need_para_break {
                out.push_str("\n\n");
            }
            // Render as a stand-alone bold line (do NOT emit a Typst `=` heading:
            // that would outrank the section titles the theme owns). A capped
            // visual emphasis keeps prose subordinate.
            out.push('*');
            out.push_str(&render_inline(text));
            out.push('*');
            need_para_break = true;
            i += 1;
            continue;
        }

        // Unordered list block.
        if unordered_marker(trimmed).is_some() {
            if need_para_break {
                out.push_str("\n\n");
            }
            let (block, next) = collect_unordered_list(&lines, i);
            out.push_str(&block);
            i = next;
            need_para_break = true;
            continue;
        }

        // Ordered list block.
        if ordered_marker(trimmed).is_some() {
            if need_para_break {
                out.push_str("\n\n");
            }
            let (block, next) = collect_ordered_list(&lines, i);
            out.push_str(&block);
            i = next;
            need_para_break = true;
            continue;
        }

        // Otherwise: a paragraph — gather consecutive non-blank, non-special
        // lines and join them with hard line breaks.
        if need_para_break {
            out.push_str("\n\n");
        }
        let (block, next) = collect_paragraph(&lines, i);
        out.push_str(&block);
        i = next;
        need_para_break = true;
    }

    out
}

/// If `line` opens a fenced code block, return its fence string (the run of
/// ``` ` ``` or `~`). Requires at least three fence chars.
fn code_fence(line: &str) -> Option<&'static str> {
    if line.starts_with("```") {
        Some("```")
    } else if line.starts_with("~~~") {
        Some("~~~")
    } else {
        None
    }
}

/// Collect a fenced code block starting at `start` (whose trimmed line opens the
/// fence) and emit it as a Typst raw block. Returns the rendered block and the
/// index just past the closing fence (or end of input).
fn collect_code_fence(lines: &[&str], start: usize, fence: &str) -> (String, usize) {
    let opener = lines[start].trim_start();
    // Info string after the fence → language label (first token only).
    let info = opener[fence.len()..].trim();
    let lang: String = info
        .split_whitespace()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '+' || *c == '_')
        .collect();

    let fence_char = fence.chars().next().unwrap();
    let mut body: Vec<&str> = Vec::new();
    let mut i = start + 1;
    while i < lines.len() {
        let t = lines[i].trim();
        let is_close = t.len() >= fence.len() && t.chars().all(|c| c == fence_char);
        if is_close {
            i += 1; // consume closing fence
            break;
        }
        body.push(lines[i]);
        i += 1;
    }

    // Choose a backtick fence longer than any backtick run in the body so the
    // content can never close the raw block early. Always at least three ticks.
    let max_run = max_backtick_run(body.iter().copied());
    let fence_len = (max_run + 1).max(3);
    let ticks = "`".repeat(fence_len);

    let mut out = String::new();
    out.push_str(&ticks);
    if !lang.is_empty() {
        out.push_str(&lang);
    }
    out.push('\n');
    for l in &body {
        out.push_str(l);
        out.push('\n');
    }
    out.push_str(&ticks);
    (out, i)
}

/// Longest run of consecutive backticks across an iterator of lines / strings.
fn max_backtick_run<'a>(items: impl Iterator<Item = &'a str>) -> usize {
    let mut max = 0;
    for s in items {
        let mut run = 0;
        for c in s.chars() {
            if c == '`' {
                run += 1;
                max = max.max(run);
            } else {
                run = 0;
            }
        }
    }
    max
}

/// Parse an ATX heading line → (level, text). `level` is clamped to 1..=6.
fn atx_heading(line: &str) -> Option<(usize, &str)> {
    let hashes = line.chars().take_while(|c| *c == '#').count();
    if hashes == 0 || hashes > 6 {
        return None;
    }
    let rest = &line[hashes..];
    // Require a space after the hashes (a `#word` is not a heading).
    if let Some(text) = rest.strip_prefix(' ') {
        // Strip an optional trailing run of '#'.
        let text = text.trim_end().trim_end_matches('#').trim_end();
        Some((hashes, text))
    } else {
        None
    }
}

/// If `line` is an unordered-list item, return the content after the marker.
fn unordered_marker(line: &str) -> Option<&str> {
    for m in ["- ", "* ", "+ "] {
        if let Some(rest) = line.strip_prefix(m) {
            return Some(rest);
        }
    }
    None
}

/// If `line` is an ordered-list item (`<digits>.` or `<digits>)`), return the
/// content after the marker.
fn ordered_marker(line: &str) -> Option<&str> {
    let digits = line.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 || digits > 9 {
        return None;
    }
    let rest = &line[digits..];
    if let Some(r) = rest.strip_prefix(". ").or_else(|| rest.strip_prefix(") ")) {
        Some(r)
    } else {
        None
    }
}

/// Collect a run of unordered-list items into Typst `- ` items.
fn collect_unordered_list(lines: &[&str], start: usize) -> (String, usize) {
    let mut out = String::new();
    let mut i = start;
    while i < lines.len() {
        let t = lines[i].trim_start();
        if let Some(content) = unordered_marker(t) {
            out.push_str("- ");
            out.push_str(&render_inline(content.trim()));
            out.push('\n');
            i += 1;
        } else {
            break;
        }
    }
    // Trim the trailing newline so paragraph spacing is handled by the caller.
    if out.ends_with('\n') {
        out.pop();
    }
    (out, i)
}

/// Collect a run of ordered-list items into Typst `+ ` items (Typst auto-numbers).
fn collect_ordered_list(lines: &[&str], start: usize) -> (String, usize) {
    let mut out = String::new();
    let mut i = start;
    while i < lines.len() {
        let t = lines[i].trim_start();
        if let Some(content) = ordered_marker(t) {
            out.push_str("+ ");
            out.push_str(&render_inline(content.trim()));
            out.push('\n');
            i += 1;
        } else {
            break;
        }
    }
    if out.ends_with('\n') {
        out.pop();
    }
    (out, i)
}

/// Collect a paragraph: consecutive lines that don't open another block kind.
/// Lines are joined with a Typst hard line break (`\ `) so authored line breaks
/// inside a paragraph are preserved.
fn collect_paragraph(lines: &[&str], start: usize) -> (String, usize) {
    let mut parts: Vec<String> = Vec::new();
    let mut i = start;
    while i < lines.len() {
        let raw = lines[i];
        let t = raw.trim_start();
        if t.trim().is_empty() {
            break;
        }
        // Stop if this line starts a different block kind.
        if code_fence(t).is_some()
            || atx_heading(t).is_some()
            || unordered_marker(t).is_some()
            || ordered_marker(t).is_some()
        {
            break;
        }
        // A trailing "  " (two spaces) is a Markdown hard break — but since we
        // already join every wrapped line with a break, we just trim trailing
        // whitespace here.
        parts.push(render_inline(raw.trim()));
        i += 1;
    }
    // Join with a Typst linebreak so soft-wrapped source lines stay on their own
    // visual line (matches the HTML renderer turning `\n` into `<br>`).
    (parts.join(" \\\n"), i)
}

/// Render inline Markdown (within a single line / list item / paragraph line)
/// into Typst inline markup. Handles, in priority order: inline code spans,
/// links, bold, italic. Everything else is escaped plain text.
fn render_inline(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    // Buffer of literal text pending escape, so we escape in runs.
    let mut text_run = String::new();

    macro_rules! flush_text {
        () => {
            if !text_run.is_empty() {
                out.push_str(&escape_text(&text_run));
                text_run.clear();
            }
        };
    }

    while i < chars.len() {
        let c = chars[i];

        // Inline code span: `code` (also handles `` `a` `` style runs).
        if c == '`' {
            // Count opening backticks.
            let open = i;
            let mut ticks = 0;
            while i < chars.len() && chars[i] == '`' {
                ticks += 1;
                i += 1;
            }
            // Find a matching run of exactly `ticks` backticks.
            if let Some(close) = find_closing_ticks(&chars, i, ticks) {
                let code: String = chars[i..close].iter().collect();
                flush_text!();
                out.push_str(&emit_inline_code(code.trim()));
                i = close + ticks;
                continue;
            } else {
                // No closing run — treat the backticks as literal text.
                for _ in 0..ticks {
                    text_run.push('`');
                }
                i = open + ticks;
                continue;
            }
        }

        // Link: [text](url)
        if c == '[' {
            if let Some((text, url, next)) = parse_link(&chars, i) {
                flush_text!();
                out.push_str("#link(\"");
                out.push_str(&escape_string_literal(&url));
                out.push_str("\")[");
                out.push_str(&render_inline(&text));
                out.push(']');
                i = next;
                continue;
            }
        }

        // Bold: **text** or __text__
        if (c == '*' || c == '_') && i + 1 < chars.len() && chars[i + 1] == c {
            let marker = c;
            if let Some(close) = find_closing_pair(&chars, i + 2, marker) {
                let inner: String = chars[i + 2..close].iter().collect();
                if !inner.is_empty() {
                    flush_text!();
                    out.push('*');
                    out.push_str(&render_inline(&inner));
                    out.push('*');
                    i = close + 2;
                    continue;
                }
            }
        }

        // Italic: *text* or _text_
        if c == '*' || c == '_' {
            if let Some(close) = find_closing_single(&chars, i + 1, c) {
                let inner: String = chars[i + 1..close].iter().collect();
                if !inner.is_empty() && !inner.contains(c) {
                    flush_text!();
                    out.push('_');
                    out.push_str(&render_inline(&inner));
                    out.push('_');
                    i = close + 1;
                    continue;
                }
            }
        }

        // Default: accumulate as literal text.
        text_run.push(c);
        i += 1;
    }

    flush_text!();
    out
}

/// Emit an inline code span as Typst, choosing a backtick fence longer than any
/// backtick run inside the code so it can never close early. Single-backtick
/// spans use `` `code` ``; if the code itself contains backticks, Typst's raw
/// requires equal-length fences, so we pad.
fn emit_inline_code(code: &str) -> String {
    let max_run = max_backtick_run(std::iter::once(code));
    let fence = "`".repeat((max_run + 1).max(1));
    // If the code starts/ends with a backtick, Typst raw needs a space pad so
    // the delimiter is unambiguous.
    let needs_pad = code.starts_with('`') || code.ends_with('`');
    let pad = if needs_pad { " " } else { "" };
    format!("{fence}{pad}{code}{pad}{fence}")
}

/// Find the index of a run of exactly `n` backticks starting at or after `from`.
/// Returns the start index of that closing run.
fn find_closing_ticks(chars: &[char], from: usize, n: usize) -> Option<usize> {
    let mut i = from;
    while i < chars.len() {
        if chars[i] == '`' {
            let mut run = 0;
            let start = i;
            while i < chars.len() && chars[i] == '`' {
                run += 1;
                i += 1;
            }
            if run == n {
                return Some(start);
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Parse a `[text](url)` link beginning at `chars[start] == '['`. Returns the
/// link text, the URL, and the index just past the closing `)`. Nested brackets
/// in the text are not supported (the first `]` closes it).
fn parse_link(chars: &[char], start: usize) -> Option<(String, String, usize)> {
    debug_assert_eq!(chars[start], '[');
    let mut i = start + 1;
    let mut text = String::new();
    while i < chars.len() && chars[i] != ']' {
        // Disallow newlines inside link text.
        if chars[i] == '\n' {
            return None;
        }
        text.push(chars[i]);
        i += 1;
    }
    if i >= chars.len() || chars[i] != ']' {
        return None;
    }
    i += 1; // past ']'
    if i >= chars.len() || chars[i] != '(' {
        return None;
    }
    i += 1; // past '('
    let mut url = String::new();
    while i < chars.len() && chars[i] != ')' {
        if chars[i] == '\n' || chars[i] == '(' {
            return None;
        }
        url.push(chars[i]);
        i += 1;
    }
    if i >= chars.len() || chars[i] != ')' {
        return None;
    }
    i += 1; // past ')'
    if url.trim().is_empty() {
        return None;
    }
    Some((text, url.trim().to_string(), i))
}

/// Find a closing double-marker (`**` / `__`) starting at `from`. Returns the
/// index of the first marker char of the closing pair.
fn find_closing_pair(chars: &[char], from: usize, marker: char) -> Option<usize> {
    let mut i = from;
    while i + 1 < chars.len() {
        if chars[i] == marker && chars[i + 1] == marker {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Find a closing single-marker (`*` / `_`) on the same logical run starting at
/// `from`. Returns the index of the closing marker. Stops at a marker that is
/// not immediately doubled.
fn find_closing_single(chars: &[char], from: usize, marker: char) -> Option<usize> {
    let mut i = from;
    while i < chars.len() {
        if chars[i] == marker {
            // A doubled marker is a bold delimiter, not a closing italic one.
            if i + 1 < chars.len() && chars[i + 1] == marker {
                i += 2;
                continue;
            }
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_whitespace_produce_empty() {
        assert_eq!(md_to_typst(""), "");
        assert_eq!(md_to_typst("   \n\n  \t"), "");
    }

    #[test]
    fn plain_text_is_escaped() {
        // All special chars must be backslash-escaped so they render literally.
        let out = md_to_typst("price is $5 #1 a=b c/d ~x");
        assert!(out.contains("\\$5"));
        assert!(out.contains("\\#1"));
        assert!(out.contains("a\\=b"));
        assert!(out.contains("c\\/d"));
        assert!(out.contains("\\~x"));
    }

    #[test]
    fn adversarial_special_chars_roundtrip_to_escaped_text() {
        // A pile of every Typst-special character with no valid Markdown.
        let nasty = r###"# $ * _ ` < > @ \ [ ] = - + / ~ " '"###;
        let out = md_to_typst(nasty);
        // Every special char that survives as literal text must be escaped
        // (preceded by a backslash). The output must not contain a bare,
        // unescaped construct opener that could break compilation. We assert the
        // dangerous singletons are escaped.
        for needle in ["\\$", "\\`", "\\<", "\\>", "\\@", "\\=", "\\~", "\\\""] {
            assert!(out.contains(needle), "missing escape {needle:?} in {out:?}");
        }
        // No unescaped function-call sigil leaking through as raw markup other
        // than our own emitted constructs (there are none here).
        assert!(!out.contains("#link"));
    }

    #[test]
    fn bold_variants() {
        assert_eq!(md_to_typst("**bold**"), "*bold*");
        assert_eq!(md_to_typst("__bold__"), "*bold*");
        assert_eq!(md_to_typst("a **b** c"), "a *b* c");
    }

    #[test]
    fn italic_variants() {
        assert_eq!(md_to_typst("*it*"), "_it_");
        assert_eq!(md_to_typst("_it_"), "_it_");
        assert_eq!(md_to_typst("a _b_ c"), "a _b_ c");
    }

    #[test]
    fn bold_then_italic_nested() {
        // **_x_** → bold wrapping italic.
        assert_eq!(md_to_typst("**_x_**"), "*_x_*");
    }

    #[test]
    fn inline_code_is_raw() {
        assert_eq!(md_to_typst("use `rm -rf`"), "use `rm -rf`");
        // Special chars inside code are NOT escaped (raw is literal).
        let out = md_to_typst("call `$x = #y`");
        assert!(out.contains("`$x = #y`"), "got {out:?}");
    }

    #[test]
    fn inline_code_with_backtick_inside_is_padded() {
        // Code containing a backtick gets a longer fence.
        let out = md_to_typst("`` a`b ``");
        assert!(
            out.contains("``a`b``") || out.contains("`` a`b ``"),
            "got {out:?}"
        );
    }

    #[test]
    fn unclosed_inline_code_is_literal() {
        let out = md_to_typst("a ` b");
        assert!(
            out.contains("\\`"),
            "unclosed backtick must be escaped, got {out:?}"
        );
    }

    #[test]
    fn link_becomes_typst_link() {
        assert_eq!(
            md_to_typst("[Owasp](https://owasp.org)"),
            "#link(\"https://owasp.org\")[Owasp]"
        );
    }

    #[test]
    fn link_url_quote_is_escaped() {
        let out = md_to_typst(r#"[x](http://a/"b)"#);
        assert!(
            out.contains("\\\""),
            "url quote must be escaped, got {out:?}"
        );
    }

    #[test]
    fn link_text_is_escaped() {
        let out = md_to_typst("[a $ b](https://x)");
        assert!(out.contains("#link(\"https://x\")[a \\$ b]"), "got {out:?}");
    }

    #[test]
    fn malformed_link_is_literal() {
        let out = md_to_typst("[text](no-close");
        assert!(
            out.contains("\\["),
            "unmatched bracket escaped, got {out:?}"
        );
    }

    #[test]
    fn unordered_list() {
        let out = md_to_typst("- one\n- two\n- three");
        assert_eq!(out, "- one\n- two\n- three");
    }

    #[test]
    fn unordered_list_star_and_plus() {
        assert_eq!(md_to_typst("* a\n+ b"), "- a\n- b");
    }

    #[test]
    fn ordered_list() {
        let out = md_to_typst("1. one\n2. two");
        assert_eq!(out, "+ one\n+ two");
    }

    #[test]
    fn list_items_render_inline_markup() {
        let out = md_to_typst("- use `x` and **y**");
        assert_eq!(out, "- use `x` and *y*");
    }

    #[test]
    fn headings_become_bold_not_typst_headings() {
        let out = md_to_typst("# Title");
        // Must NOT emit a Typst `=` heading (would outrank section titles).
        assert!(
            !out.contains('='),
            "heading must not become a typst heading: {out:?}"
        );
        assert_eq!(out, "*Title*");
    }

    #[test]
    fn deep_heading_still_bold() {
        assert_eq!(md_to_typst("###### Deep"), "*Deep*");
    }

    #[test]
    fn seven_hashes_is_not_a_heading() {
        let out = md_to_typst("####### too deep");
        // 7 hashes is not a heading → escaped text.
        assert!(out.contains("\\#"), "got {out:?}");
    }

    #[test]
    fn code_fence_basic() {
        let out = md_to_typst("```python\nprint(1)\n```");
        assert!(
            out.starts_with("```python\nprint(1)\n```") || out.contains("```python\nprint(1)\n"),
            "got {out:?}"
        );
        assert!(out.contains("print(1)"));
    }

    #[test]
    fn code_fence_no_lang() {
        let out = md_to_typst("```\nraw\n```");
        assert!(out.contains("raw"));
        assert!(out.starts_with("```"));
    }

    #[test]
    fn code_fence_content_not_escaped() {
        let out = md_to_typst("```\n$x #y *z*\n```");
        // Inside a code fence, specials stay literal (raw block).
        assert!(out.contains("$x #y *z*"), "got {out:?}");
    }

    #[test]
    fn code_fence_with_backticks_inside_uses_longer_fence() {
        let out = md_to_typst("```\nhas ``` inside\n```");
        // The emitted fence must be longer than 3 ticks to contain the body.
        assert!(out.contains("````"), "fence must be padded, got {out:?}");
    }

    #[test]
    fn paragraphs_separated_by_blank_line() {
        let out = md_to_typst("para one\n\npara two");
        assert_eq!(out, "para one\n\npara two");
    }

    #[test]
    fn soft_wrapped_lines_get_line_break() {
        let out = md_to_typst("line a\nline b");
        assert_eq!(out, "line a \\\nline b");
    }

    #[test]
    fn mixed_document_compiles_to_expected_structure() {
        let md = "# Overview\n\nSome **bold** and a [link](https://x).\n\n- item `a`\n- item b\n\n```rust\nlet x = 1;\n```";
        let out = md_to_typst(md);
        assert!(out.contains("*Overview*"));
        assert!(out.contains("*bold*"));
        assert!(out.contains("#link(\"https://x\")[link]"));
        assert!(out.contains("- item `a`"));
        assert!(out.contains("```rust\nlet x = 1;\n```"));
    }

    #[test]
    fn backslash_in_text_is_escaped_first() {
        let out = md_to_typst(r"a\b");
        assert!(
            out.contains("\\\\"),
            "backslash must be escaped, got {out:?}"
        );
    }
}
