fn main() {
    // Embed our asInvoker manifest instead of Tauri's default so the exe never forces a UAC prompt.
    println!("cargo:rerun-if-changed=app.manifest");
    let windows = tauri_build::WindowsAttributes::new().app_manifest(include_str!("app.manifest"));
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("failed to run tauri-build");
}
