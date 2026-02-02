fn main() {
    println!("cargo:rerun-if-changed=src/file_lock/process_time.c");
    println!("cargo:rerun-if-changed=src/file_lock/flock.c");

    cc::Build::new()
        .file("src/file_lock/process_time.c")
        .file("src/file_lock/flock.c")
        // .warnings(true)
        // .extra_warnings(true)
        // .cargo_warnings(true)
        // .warnings_into_errors(true)
        .compile("vci-native");
}
