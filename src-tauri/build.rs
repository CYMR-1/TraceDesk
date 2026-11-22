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
    println!("cargo:rerun-if-changed=../frontend/dist");
    println!("cargo:rerun-if-changed=../frontend/dist/index.html");
    tauri_build::build();

    // 在 Windows 平台上，`tauri_build::build()` 仅将 `resource.lib`（包含
    // `tauri-plugin-dialog`/`rfd` 调用 `comctl32!TaskDialogIndirect` 所需的
    // Common Controls v6 清单）链接到可执行目标（`rustc-link-arg-bins`）。
    // `tests/` 下的集成测试二进制同样会链接 `tracedesk_desktop_lib`，因此需将
    // `resource.lib` 一并传递给测试目标。
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some()
        && let Ok(out_dir) = std::env::var("OUT_DIR")
    {
        let resource_lib = Path::new(&out_dir).join("resource.lib");
        if resource_lib.exists() {
            println!("cargo:rustc-link-arg-tests={}", resource_lib.display());
        }
    }
}
