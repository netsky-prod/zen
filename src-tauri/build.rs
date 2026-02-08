fn main() {
    // Embed Windows manifest requiring admin privileges (no VERSION info — Tauri handles that)
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" {
        embed_resource::compile("app-manifest.rc", embed_resource::NONE);
    }

    tauri_build::build()
}
