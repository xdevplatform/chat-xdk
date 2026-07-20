// Minimal build script - codegen moved to `make codegen`
fn main() {
    println!("cargo:rerun-if-changed=../../dm.thrift");
}
