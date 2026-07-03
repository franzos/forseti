//! CI guards for the .ftl catalogs. Key parity across locales (messages
//! AND attributes), and a scan proving no rendered placeholder leaks.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fluent_syntax::ast;
use fluent_syntax::parser;
use regex::Regex;

/// Collect message ids and (message, attribute) pairs from every .ftl in a
/// locale dir. Terms and comments are skipped; attribute-only messages are
/// recorded by their attribute keys only.
fn keys_for_locale(dir: &Path) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for entry in fs::read_dir(dir).expect("locale dir readable") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("ftl") {
            continue;
        }
        let src = fs::read_to_string(&path).unwrap();
        let resource = match parser::parse(src.as_str()) {
            Ok(r) => r,
            Err((_, errs)) => panic!(
                "{}: {} parse error(s), first: {:?}",
                path.display(),
                errs.len(),
                errs.first()
            ),
        };
        for entry in resource.body {
            if let ast::Entry::Message(m) = entry {
                if m.value.is_some() {
                    keys.insert(m.id.name.to_string());
                }
                for attr in m.attributes {
                    keys.insert(format!("{}.{}", m.id.name, attr.id.name));
                }
            }
        }
    }
    keys
}

fn collect_html_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(collect_html_files(&path));
        } else if path.extension().and_then(|e| e.to_str()) == Some("html") {
            out.push(path);
        }
    }
    out
}

/// Extracts every i18n key referenced in templates and asserts each one is
/// present in the en catalog. A missing key renders the literal placeholder
/// "Unknown localization key:" at runtime, invisible to the parity test above.
#[test]
fn templates_reference_only_defined_i18n_keys() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"));
    let defined = keys_for_locale(&base.join("locales").join("en"));

    // Covers chrome.t("KEY"), chrome.tv1("KEY", ...), chrome.tv_count("KEY", ...)
    // and chrome.ta("KEY", "ATTR") -> key "KEY.ATTR".
    // Order: longer names before the plain `t` alternative so alternation is unambiguous.
    let re =
        Regex::new(r#"chrome\.(tv_count|tv3|tv2|tv1|ta|t)\(\s*"([^"]+)"(?:\s*,\s*"([^"]+)")?"#)
            .expect("static regex");

    let mut missing: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut total_refs: usize = 0;

    let templates_dir = base.join("templates");
    let mut html_files = collect_html_files(&templates_dir);
    html_files.sort();

    for path in &html_files {
        let src = fs::read_to_string(path).expect("template readable");
        let rel = path
            .strip_prefix(base)
            .unwrap_or(path)
            .display()
            .to_string();
        for cap in re.captures_iter(&src) {
            total_refs += 1;
            let method = cap.get(1).unwrap().as_str();
            let key_part = cap.get(2).unwrap().as_str();
            let key = if method == "ta" {
                match cap.get(3).map(|m| m.as_str()) {
                    Some(attr) => format!("{key_part}.{attr}"),
                    None => key_part.to_string(),
                }
            } else {
                key_part.to_string()
            };
            if !defined.contains(&key) {
                missing.entry(key).or_default().push(rel.clone());
            }
        }
    }

    assert!(
        missing.is_empty(),
        "scanned {total_refs} template i18n references; {} key(s) missing from locales/en:\n{}",
        missing.len(),
        missing
            .iter()
            .map(|(k, files)| format!("  {k}  ({})", files.join(", ")))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Map each `kratos-<id>` message to the set of Fluent variables it
/// interpolates. `kratos.ftl` is flat single-line messages, so a line scan is
/// exact here.
fn kratos_vars(path: &Path) -> BTreeMap<String, BTreeSet<String>> {
    let var_re = Regex::new(r"\$([a-zA-Z_][a-zA-Z0-9_]*)").expect("static regex");
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let src = fs::read_to_string(path).expect("kratos.ftl readable");
    for line in src.lines() {
        let Some((id, text)) = line.split_once(" = ") else {
            continue;
        };
        let id = id.trim();
        if !id.starts_with("kratos-") {
            continue;
        }
        let vars = var_re
            .captures_iter(text)
            .map(|c| c[1].to_string())
            .collect::<BTreeSet<_>>();
        out.insert(id.to_string(), vars);
    }
    out
}

/// A translated Kratos message must interpolate exactly the same variables as
/// its English source. A de message that references `$provider_name` where en
/// uses `$provider` (or drops the variable) formats to the English fallback at
/// runtime; this catches that at build time.
#[test]
fn kratos_placeables_match_across_locales() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("locales");
    let en = kratos_vars(&base.join("en").join("kratos.ftl"));
    let de = kratos_vars(&base.join("de").join("kratos.ftl"));
    let mut mismatches = Vec::new();
    for (id, en_vars) in &en {
        match de.get(id) {
            Some(de_vars) if de_vars == en_vars => {}
            Some(de_vars) => mismatches.push(format!("  {id}: en {en_vars:?} != de {de_vars:?}")),
            None => mismatches.push(format!("  {id}: missing in de")),
        }
    }
    assert!(
        mismatches.is_empty(),
        "Kratos placeable drift:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn locales_have_identical_key_sets() {
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("locales");
    let en = keys_for_locale(&base.join("en"));
    let locale = "de";
    let other = keys_for_locale(&base.join(locale));
    let missing: Vec<_> = en.difference(&other).collect();
    let extra: Vec<_> = other.difference(&en).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "locale {locale}: missing {missing:?}, extra {extra:?}"
    );
}
