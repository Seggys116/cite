fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    #[cfg(windows)]
    {
        // The icon is embedded in the exe so Explorer and the taskbar show the wordmark.
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        if let Err(err) = res.compile() {
            panic!("could not embed the Windows icon: {err}");
        }
    }
}
