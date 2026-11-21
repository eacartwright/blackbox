// Embed the BlackBox icon in bbx.exe (Explorer, setup, uninstall entry).
fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml"); // version info (package.metadata.winresource)
    println!("cargo:rerun-if-changed=../../assets/blackbox.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../../assets/blackbox.ico");
        res.compile().expect("embedding the icon resource");
    }
}
