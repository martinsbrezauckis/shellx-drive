fn main() {
    #[cfg(feature = "desktop-shell")]
    tauri_build::build();
}
