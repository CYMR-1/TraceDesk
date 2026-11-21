use std::fs;
use std::path::Path;

fn main() {
    let dist_dir = Path::new("../frontend/dist");
    if !dist_dir.exists() {
        let _ = fs::create_dir_all(dist_dir);
        let index_html = dist_dir.join("index.html");
        if !index_html.exists() {
            let _ = fs::write(
                &index_html,
                "<!doctype html><html><body>TraceDesk</body></html>",
            );
        }
    }
    tauri_build::build();

    // On Windows, `tauri_build::build()` links `resource.lib` (containing the Common Controls v6
    // manifest required by `comctl32!TaskDialogIndirect` from `tauri-plugin-dialog`/`rfd`) only
    // into bin targets (`rustc-link-arg-bins`). Integration test binaries in `tests/` also link
    // against `tracedesk_desktop_lib`, so pass `resource.lib` to test targets as well.
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some()
        && let Ok(out_dir) = std::env::var("OUT_DIR")
    {
        let resource_lib = Path::new(&out_dir).join("resource.lib");
        if resource_lib.exists() {
            println!("cargo:rustc-link-arg-tests={}", resource_lib.display());
        }
    }
}
