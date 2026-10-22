// Minimal build script - codegen moved to `make codegen`
fn main() {
    println!("cargo::rerun-if-changed=../../dm.thrift");

    // The `bindings` feature drives the feature switches, so only this
    // repository's builds may enable it. They set CHAT_XDK_BINDINGS through
    // the repository's .cargo/config.toml, which Cargo never reads for a crate
    // that depends on chat-xdk-core.
    println!("cargo::rustc-check-cfg=cfg(chat_xdk_bindings)");
    println!("cargo::rerun-if-env-changed=CHAT_XDK_BINDINGS");
    if std::env::var("CHAT_XDK_BINDINGS").as_deref() == Ok("1") {
        println!("cargo::rustc-cfg=chat_xdk_bindings");
    }
}
