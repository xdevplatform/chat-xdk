fn main() {
    // Generate the C# P/Invoke layer from the Rust FFI source.
    //
    // The output file is committed to the repo so C# consumers don't need a
    // Rust toolchain — they just reference the pre-built native library.
    // Re-run `cargo build -p chat-xdk-dotnet` to regenerate after API changes.
    csbindgen::Builder::default()
        .input_extern_file("src/lib.rs")
        .csharp_dll_name("chat_xdk_dotnet")
        .csharp_namespace("ChatXdk")
        .csharp_class_name("NativeMethods")
        .csharp_class_accessibility("internal")
        .generate_csharp_file("dotnet/ChatXdk/NativeMethods.g.cs")
        .unwrap();
}
