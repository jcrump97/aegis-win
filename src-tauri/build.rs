fn main() {
    // Embed our asInvoker manifest instead of Tauri's default so the exe never forces a UAC prompt.
    println!("cargo:rerun-if-changed=app.manifest");
    let windows = tauri_build::WindowsAttributes::new().app_manifest(include_str!("app.manifest"));
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("failed to run tauri-build");
    // The exe's own DLL imports load from System32 only, never from the folder
    // it runs in (DLL planting; LOAD_LIBRARY_SEARCH_SYSTEM32). Known DLLs are
    // unaffected; WebView2 is loaded by full path.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
}
