// Embedded wrapper around UniFFI's bindgen entry point. UniFFI 0.28+
// no longer ships `uniffi-bindgen` as a top-level cargo-installable
// binary; the canonical pattern is for each FFI crate to expose its
// own copy via `uniffi::uniffi_bindgen_main()`.
//
// Invoked from CI (mobile.yml + sdk releases) as:
//   cargo run -p dnsmesh-ffi --features cli --bin uniffi-bindgen -- \
//     generate --library <path-to-dylib> --language swift --out-dir bindings/swift

fn main() {
    uniffi::uniffi_bindgen_main()
}
