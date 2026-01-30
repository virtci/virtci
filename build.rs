fn main() {
    println!("cargo:rerun-if-changed=src/transfer_lock/process_time.c");
    println!("cargo:rerun-if-changed=src/transfer_lock/transfer_lock.c");

    cc::Build::new()
        .file("src/transfer_lock/process_time.c")
        .file("src/transfer_lock/transfer_lock.c")
        .compile("vci-native");
}
