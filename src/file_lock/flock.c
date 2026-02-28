// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

#include <stdbool.h>

#if defined(__APPLE__) || defined(__linux__)
#include <errno.h>
#include <sys/file.h>

bool try_lock_file_exclusive_native(int fd) {
  int result = flock(fd, LOCK_EX | LOCK_NB);
  return result == 0;
}

void unlock_file_native(int fd) { (void)flock(fd, LOCK_UN); }

#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

bool try_lock_file_exclusive_native(intptr_t handle) {
  OVERLAPPED overlapped = {0};
  BOOL result = LockFileEx((HANDLE)handle,
                           LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                           0, 1, 0, &overlapped);
  return result != 0;
}

void unlock_file_native(intptr_t handle) {
  OVERLAPPED overlapped = {0};
  UnlockFileEx((HANDLE)handle, 0, 1, 0, &overlapped);
}

#else
#error "Unsupported platform"
#endif
