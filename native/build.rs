// Generates the C header (native/include/spl_native.h) from the crate's
// `extern "C"` surface using cbindgen, so the C++ side never hand-maintains it.
use std::path::PathBuf;

fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let out_dir = PathBuf::from(&crate_dir).join("include");
    let _ = std::fs::create_dir_all(&out_dir);
    let header = out_dir.join("spl_native.h");

    match cbindgen::generate(&crate_dir) {
        Ok(bindings) => {
            bindings.write_to_file(&header);
        }
        Err(e) => {
            // Don't fail the build on header generation; the C++ side can fall
            // back to its own declarations. Surface it as a warning instead.
            println!("cargo:warning=cbindgen failed: {e}");
        }
    }

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
