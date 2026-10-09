//! The Playwright and Chromium versions of the sandbox (`sandbox/package.json`) these runs use.
fn main() {
    let file = "../../sandbox/package.json";
    println!("cargo:rerun-if-changed={file}");
    let text = std::fs::read_to_string(file).expect("sandbox/package.json");
    for (name, key) in [("PLAYWRIGHT_VERSION", "\"@playwright/test\""), ("CHROMIUM_VERSION", "\"chromium\"")] {
        let line = text.lines().find(|line| line.trim_start().starts_with(key)).expect("version line");
        let version = line.split('"').nth(3).expect("quoted version");
        println!("cargo:rustc-env={name}={version}");
    }
}
