use std::env;
use std::fs;
use std::path::Path;

// cargo doesn't track files inside include_dir!, so emit rerun-if-changed per file.
fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    watch(&root.join("static"));
    watch(&root.join("locales"));
}

fn watch(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());

    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let child = entry.path();
        if child.is_dir() {
            watch(&child);
        } else {
            println!("cargo:rerun-if-changed={}", child.display());
        }
    }
}
