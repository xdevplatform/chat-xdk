fn main() {
    // When building the Python extension directly with `cargo build` (without maturin),
    // macOS needs `-undefined dynamic_lookup` so we don't have to link against a
    // specific `libpythonX.Y` at build time.
    //
    // This matches the standard way Python C-extension modules are linked on macOS.
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-arg=-undefined");
        println!("cargo:rustc-link-arg=dynamic_lookup");
    }
}
