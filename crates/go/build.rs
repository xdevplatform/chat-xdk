fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = format!("{}/../../go/chatxdk/include", crate_dir);

    // Ensure include directory exists
    std::fs::create_dir_all(&out_dir).expect("Failed to create include directory");

    let config =
        cbindgen::Config::from_file(format!("{}/cbindgen.toml", crate_dir)).unwrap_or_default();

    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate C bindings")
        .write_to_file(format!("{}/chat_xdk.h", out_dir));
}
