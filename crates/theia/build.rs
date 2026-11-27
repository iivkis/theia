fn main() {
    // Match the explicit runtime worker stack reserve on the initial
    // Windows process thread. This reserves address space, not 8 MiB RSS.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        println!("cargo:rustc-link-arg-bin=theia=/STACK:8388608");
    }
}
