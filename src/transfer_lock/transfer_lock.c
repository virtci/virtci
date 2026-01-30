#include <stdbool.h>

#if defined(__APPLE__) || defined(__linux__)
#include <sys/file.h>
#include <errno.h>

bool try_lock_file_exclusive_native(int fd) {
    int result = flock(fd, LOCK_EX | LOCK_NB);
    return result == 0;
}

void unlock_file_native(int fd) {
    flock(fd, LOCK_UN);
}

#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

bool try_lock_file_exclusive_native(intptr_t handle) {
    OVERLAPPED overlapped = {0};
    // Lock the first byte (or any range) - we just need mutual exclusion
    BOOL result = LockFileEx(
        (HANDLE)handle,
        LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
        0,       // reserved
        1,       // lock 1 byte
        0,       // high-order bytes of length
        &overlapped
    );
    return result != 0;
}

void unlock_file_native(intptr_t handle) {
    OVERLAPPED overlapped = {0};
    UnlockFileEx((HANDLE)handle, 0, 1, 0, &overlapped);
}

#else
#error "Unsupported platform"
#endif
