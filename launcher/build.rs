fn main() {
    // Embed the app icon and an asInvoker manifest. Without a manifest, Windows "installer detection"
    // can force a UAC prompt on an exe that looks like a setup program.
    println!("cargo:rerun-if-changed=launcher.rc");
    println!("cargo:rerun-if-changed=launcher.manifest");
    println!("cargo:rerun-if-changed=../src-tauri/icons/icon.ico");
    embed_resource::compile("launcher.rc", embed_resource::NONE)
        .manifest_required()
        .expect("failed to embed launcher resources");
}
