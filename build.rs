// Embeds the upstream Prisma migrations (prisma/migrations/<name>/migration.sql for SQLite,
// prisma/migrations-postgresql/<name>/migration.sql for PostgreSQL)
// so the binary can apply them with Prisma-compatible bookkeeping.
use std::{env, fs, path::Path};

fn embed(dir: &str, var: &str, out: &mut String) {
    let dir = Path::new(dir);
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap_or_else(|_| panic!("{}", dir.display()))
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("migration.sql").is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    out.push_str(&format!("pub static {var}: &[(&str, &str)] = &[\n"));
    for name in &names {
        let path = fs::canonicalize(dir.join(name).join("migration.sql")).unwrap();
        out.push_str(&format!("    ({name:?}, include_str!({:?})),\n", path.display().to_string()));
    }
    out.push_str("];\n");
}

fn main() {
    println!("cargo:rerun-if-changed=VERSION");
    let mut out = String::new();
    embed("prisma/migrations", "MIGRATIONS", &mut out);
    out.push_str("#[cfg(feature = \"postgres\")]\n");
    embed("prisma/migrations-postgresql", "MIGRATIONS_PG", &mut out);
    let dest = Path::new(&env::var("OUT_DIR").unwrap()).join("migrations.rs");
    fs::write(dest, out).unwrap();
}
