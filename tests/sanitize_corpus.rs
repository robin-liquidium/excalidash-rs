//! Sanitiser parity: outputs of upstream's compiled security.js (DOMPurify + jsdom, captured
//! from zimengxiong/excalidash-backend:0.6.5) vs this port, on a fixed corpus.
use excalidash_rs::security::{sanitize_svg, sanitize_text};
use serde_json::Value;

fn load(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap()
}

#[test]
fn matches_dompurify_on_corpus() {
    let input = load("sanitize_corpus.input.json");
    let expected = load("sanitize_corpus.expected.json");
    let mut failures = vec![];
    for (i, t) in input["texts"].as_array().unwrap().iter().enumerate() {
        let t = t.as_str().unwrap();
        let got = sanitize_text(t, 1000);
        if got != expected["texts"][i].as_str().unwrap() {
            failures.push(format!("text[{i}] {t:?}\n   upstream {:?}\n   rust     {got:?}", expected["texts"][i]));
        }
        let got = sanitize_text(t, 12);
        if got != expected["textsShort"][i].as_str().unwrap() {
            failures.push(format!("text12[{i}] {t:?}\n   upstream {:?}\n   rust     {got:?}", expected["textsShort"][i]));
        }
    }
    for (i, s) in input["svgs"].as_array().unwrap().iter().enumerate() {
        let got = sanitize_svg(s.as_str().unwrap());
        if got != expected["svgs"][i].as_str().unwrap() {
            failures.push(format!("svg[{i}]\n   upstream {}\n   rust     {got}", expected["svgs"][i]));
        }
    }
    assert!(failures.is_empty(), "{} mismatches:\n{}", failures.len(), failures.join("\n"));
}

/// Optional extra corpus (not committed), e.g. real previews: EXRS_SANITIZE_EXTRA=<dir>
/// containing input.json {"svgs": [...]} and expected.json from upstream.
#[test]
fn matches_dompurify_on_extra_corpus() {
    let Ok(dir) = std::env::var("EXRS_SANITIZE_EXTRA") else { return };
    let read = |n: &str| -> Value { serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{n}")).unwrap()).unwrap() };
    let (input, expected) = (read("input.json"), read("expected.json"));
    let svgs = input["svgs"].as_array().unwrap();
    let mut bad = 0;
    for (i, s) in svgs.iter().enumerate() {
        let got = sanitize_svg(s.as_str().unwrap());
        if got != expected["svgs"][i].as_str().unwrap() {
            bad += 1;
            println!("svg[{i}]\n   upstream {}\n   rust     {got}", expected["svgs"][i]);
        }
    }
    println!("extra corpus: {}/{} identical", svgs.len() - bad, svgs.len());
    assert_eq!(bad, 0);
}
