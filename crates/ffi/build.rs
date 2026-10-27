fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    // The C header the Go package (and any C consumer) compiles against.
    let include_dir = format!("{crate_dir}/../../go/chatxdk/include");
    std::fs::create_dir_all(&include_dir).expect("Failed to create include directory");
    let config = cbindgen::Config::from_file(format!("{crate_dir}/cbindgen.toml"))
        .expect("Unable to read cbindgen.toml");
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file(format!("{include_dir}/chat_xdk.h"));

    // The C# P/Invoke layer. It is committed so .NET consumers need no Rust
    // toolchain; this build regenerates it after any change to the C ABI.
    let mut csharp = csbindgen::Builder::default();
    for file in [
        "src/lib.rs",
        "src/conversation.rs",
        "src/encrypt.rs",
        "src/events.rs",
        "src/files.rs",
        "src/prepare.rs",
        "src/signing.rs",
    ] {
        csharp = csharp.input_extern_file(file);
    }
    csharp
        .csharp_dll_name("chat_xdk_ffi")
        .csharp_namespace("ChatXdk")
        .csharp_class_name("NativeMethods")
        .csharp_class_accessibility("internal")
        .generate_csharp_file(format!(
            "{crate_dir}/../dotnet/dotnet/ChatXdk/NativeMethods.g.cs"
        ))
        .unwrap();
}
