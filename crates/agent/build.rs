//! The agent version comes from `version.txt` at the repository root, which release-please sets.
fn main() {
    let file = "../../version.txt";
    println!("cargo:rerun-if-changed={file}");
    let version = std::fs::read_to_string(file).expect("version.txt");
    println!("cargo:rustc-env=AGENT_VERSION={}", version.trim());
}
