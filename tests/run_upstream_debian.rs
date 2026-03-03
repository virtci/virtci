use virtci::{run_virtci_with_args, vm_image::list::load_all_images};

#[test]
#[ignore]
fn run_debian_upstream_x64() {
    const VM_IMAGE_NAME: &'static str = "TEST_run_debian_upstream_x64";
    let paths = virtci::VciGlobalPaths::default();

    {
        let all_images = load_all_images(&paths.home);
        let contains_image = all_images.iter().any(|img| img.name == VM_IMAGE_NAME);
        if contains_image {
            run_virtci_with_args(&paths, &["remove", VM_IMAGE_NAME, "--force"]);
        }
    }

    run_virtci_with_args(
        &paths,
        &[
            "setup",
            "--qemu",
            "--from",
            "tests/upstream_image/test-debian-x64.json",
            "--name",
            VM_IMAGE_NAME,
        ],
    );

    {
        let all_images = load_all_images(&paths.home);
        let contains_image = all_images.iter().any(|img| img.name == VM_IMAGE_NAME);
        assert!(contains_image);
    }

    run_virtci_with_args(
        &paths,
        &[
            "run",
            "tests/upstream_image/basic-test-debian.yml",
            "--image",
            VM_IMAGE_NAME,
        ],
    );

    {
        run_virtci_with_args(&paths, &["remove", VM_IMAGE_NAME, "--force"]);
        let all_images = load_all_images(&paths.home);
        let contains_image = all_images.iter().any(|img| img.name == VM_IMAGE_NAME);
        assert!(!contains_image);
    }
}

#[test]
#[ignore]
fn run_debian_upstream_arm64() {
    const VM_IMAGE_NAME: &'static str = "TEST_run_debian_upstream_arm64";
    let paths = virtci::VciGlobalPaths::default();

    {
        let all_images = load_all_images(&paths.home);
        let contains_image = all_images.iter().any(|img| img.name == VM_IMAGE_NAME);
        if contains_image {
            run_virtci_with_args(&paths, &["remove", VM_IMAGE_NAME, "--force"]);
        }
    }

    run_virtci_with_args(
        &paths,
        &[
            "setup",
            "--qemu",
            "--from",
            "tests/upstream_image/test-debian-arm64.json",
            "--name",
            VM_IMAGE_NAME,
        ],
    );

    {
        let all_images = load_all_images(&paths.home);
        let contains_image = all_images.iter().any(|img| img.name == VM_IMAGE_NAME);
        assert!(contains_image);
    }

    run_virtci_with_args(
        &paths,
        &[
            "run",
            "tests/upstream_image/basic-test-debian.yml",
            "--image",
            VM_IMAGE_NAME,
        ],
    );

    {
        run_virtci_with_args(&paths, &["remove", VM_IMAGE_NAME, "--force"]);
        let all_images = load_all_images(&paths.home);
        let contains_image = all_images.iter().any(|img| img.name == VM_IMAGE_NAME);
        assert!(!contains_image);
    }
}
