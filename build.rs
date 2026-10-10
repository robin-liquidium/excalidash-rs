// Embeds the upstream Prisma SQLite migrations (prisma/migrations/<name>/migration.sql)
// so the binary can apply them with Prisma-compatible bookkeeping.
use std::{env, fs, path::Path};

fn main() {
    let dir = Path::new("prisma/migrations");
    println!("cargo:rerun-if-changed=prisma/migrations");
    println!("cargo:rerun-if-changed=VERSION");
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("prisma/migrations")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("migration.sql").is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    let mut out = String::from("pub static MIGRATIONS: &[(&str, &str)] = &[\n");
    for name in &names {
        let path = fs::canonicalize(dir.join(name).join("migration.sql")).unwrap();
        out.push_str(&format!("    ({name:?}, include_str!({:?})),\n", path.display().to_string()));
    }
    out.push_str("];\n");
    let dest = Path::new(&env::var("OUT_DIR").unwrap()).join("migrations.rs");
    fs::write(dest, out).unwrap();
}
