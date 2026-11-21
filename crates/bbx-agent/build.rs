// Embed the tray icons in bbx-agent.exe. Resource 1 (recording) is also the
// exe's own icon; resource 2 is shown while recording is stopped.
// Keep the ids in sync with ICON_RECORDING / ICON_STOPPED in main.rs.
fn main() {
    println!("cargo:rerun-if-changed=../../assets/blackbox.ico");
    println!("cargo:rerun-if-changed=../../assets/blackbox-stopped.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon_with_id("../../assets/blackbox.ico", "1");
        res.set_icon_with_id("../../assets/blackbox-stopped.ico", "2");
        res.compile().expect("embedding the icon resources");
    }
}
