//! Smoke tests for the two load-bearing primitives: SQLCipher encryption
//! (round-trip + wrong-key rejection) and in-process Typst -> PDF rendering.
//! Kept as fast guards against dependency/toolchain regressions.

use std::path::PathBuf;

fn tmp_db() -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("pwn2report-spike-{}.db", uuid::Uuid::new_v4()));
    p
}

#[test]
fn sqlcipher_roundtrip_and_wrong_key_fails() {
    use rusqlite::Connection;
    let path = tmp_db();

    // create encrypted db: PRAGMA key MUST run before any other statement
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA key = 'correct horse battery';")
            .unwrap();
        conn.execute_batch("CREATE TABLE t(x INTEGER);").unwrap();
        conn.execute("INSERT INTO t(x) VALUES (?1)", [42]).unwrap();
    }

    // reopen with correct key -> data readable
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA key = 'correct horse battery';")
            .unwrap();
        let v: i64 = conn.query_row("SELECT x FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(v, 42);
    }

    // reopen with wrong key -> first real query fails ("file is not a database")
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA key = 'wrong key';").unwrap();
        let r = conn.query_row("SELECT x FROM t", [], |r| r.get::<_, i64>(0));
        assert!(r.is_err(), "wrong passphrase must not decrypt the database");
    }

    // sanity: file is NOT a plaintext sqlite db (no "SQLite format 3" header)
    let bytes = std::fs::read(&path).unwrap();
    assert!(
        !bytes.starts_with(b"SQLite format 3\0"),
        "encrypted db must not have a plaintext sqlite header"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn typst_compiles_to_pdf_with_injected_input() {
    use typst::foundations::{Dict, IntoValue, Str};
    use typst_as_lib::typst_kit_options::TypstKitFontOptions;
    use typst_as_lib::TypstEngine;

    static TEMPLATE: &str = r#"
#import sys: inputs
#set page(paper: "a4")
= Security Report
Client: #inputs.client
Severity: #inputs.severity
"#;

    let engine = TypstEngine::builder()
        .main_file(TEMPLATE)
        .search_fonts_with(
            TypstKitFontOptions::default()
                .include_system_fonts(false)
                .include_embedded_fonts(true),
        )
        .build();

    let mut input = Dict::new();
    input.insert(Str::from("client"), "ACME Corp".into_value());
    input.insert(Str::from("severity"), "Critical".into_value());

    let doc = engine
        .compile_with_input(input)
        .output
        .expect("typst compile failed");

    let pdf = typst_pdf::pdf(&doc, &Default::default()).expect("pdf generation failed");

    assert!(pdf.starts_with(b"%PDF"), "output must be a PDF");
    assert!(
        pdf.len() > 1000,
        "PDF suspiciously small: {} bytes",
        pdf.len()
    );
}
