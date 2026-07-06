// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

#include <stddef.h>
#include <stdint.h>

/// Bytes available to a non-privileged user on the filesystem that holds `path`.
/// `path` is UTF-8 and NOT null terminated; it is `path_len` bytes long.
/// Returns -1 on any error (e.g. the path does not exist).
int64_t vci_fs_avail_bytes_native(const char *path, size_t path_len);

/// Total bytes of the filesystem that holds `path`. Same conventions as above.
int64_t vci_fs_total_bytes_native(const char *path, size_t path_len);

#if defined(__APPLE__) || defined(__linux__)

#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>

static int vci_statvfs_path(const char *path, size_t path_len, struct statvfs *out) {
    if (path == NULL || path_len == 0) {
        return -1;
    }
    char *p = malloc(path_len + 1);
    if (p == NULL) {
        return -1;
    }
    memcpy(p, path, path_len);
    p[path_len] = '\0';
    const int result = statvfs(p, out);
    free(p);
    return result;
}

int64_t vci_fs_avail_bytes_native(const char *path, size_t path_len) {
    struct statvfs st;
    if (vci_statvfs_path(path, path_len, &st) != 0) {
        return -1;
    }
    // f_frsize is the fundamental block size; f_bavail is blocks free to non-root.
    return (int64_t)st.f_bavail * (int64_t)st.f_frsize;
}

int64_t vci_fs_total_bytes_native(const char *path, size_t path_len) {
    struct statvfs st;
    if (vci_statvfs_path(path, path_len, &st) != 0) {
        return -1;
    }
    return (int64_t)st.f_blocks * (int64_t)st.f_frsize;
}

#elif defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#include <limits.h>
#include <stdlib.h>
#include <windows.h>

/// Allocated (on-disk) size of a single file, accounting for sparse/compressed files.
/// Windows only: unix reads `st_blocks` straight from std's `MetadataExt`. Returns -1 on error.
int64_t vci_file_allocated_bytes_native(const char *path, size_t path_len);

static wchar_t *vci_to_wide(const char *path, size_t path_len) {
    if (path == NULL || path_len == 0 || path_len > (size_t)INT_MAX) {
        return NULL;
    }
    const int wide_len = MultiByteToWideChar(CP_UTF8, 0, path, (int)path_len, NULL, 0);
    if (wide_len <= 0) {
        return NULL;
    }
    wchar_t *wide = malloc(((size_t)wide_len + 1) * sizeof(wchar_t));
    if (wide == NULL) {
        return NULL;
    }
    MultiByteToWideChar(CP_UTF8, 0, path, (int)path_len, wide, wide_len);
    wide[wide_len] = L'\0';
    return wide;
}

static int vci_disk_free(const char *path, size_t path_len, ULARGE_INTEGER *avail,
                         ULARGE_INTEGER *total) {
    wchar_t *wide = vci_to_wide(path, path_len);
    if (wide == NULL) {
        return -1;
    }
    // `avail` is the free bytes usable by the calling user (respects quotas), which mirrors the
    // unix `f_bavail` semantics above.
    const BOOL ok = GetDiskFreeSpaceExW(wide, avail, total, NULL);
    free(wide);
    return ok ? 0 : -1;
}

int64_t vci_fs_avail_bytes_native(const char *path, size_t path_len) {
    ULARGE_INTEGER avail;
    ULARGE_INTEGER total;
    if (vci_disk_free(path, path_len, &avail, &total) != 0) {
        return -1;
    }
    return (int64_t)avail.QuadPart;
}

int64_t vci_fs_total_bytes_native(const char *path, size_t path_len) {
    ULARGE_INTEGER avail;
    ULARGE_INTEGER total;
    if (vci_disk_free(path, path_len, &avail, &total) != 0) {
        return -1;
    }
    return (int64_t)total.QuadPart;
}

int64_t vci_file_allocated_bytes_native(const char *path, size_t path_len) {
    wchar_t *wide = vci_to_wide(path, path_len);
    if (wide == NULL) {
        return -1;
    }
    DWORD high = 0;
    const DWORD low = GetCompressedFileSizeW(wide, &high);
    free(wide);
    if (low == INVALID_FILE_SIZE && GetLastError() != NO_ERROR) {
        return -1;
    }
    return (int64_t)(((uint64_t)high << 32) | (uint64_t)low);
}

#else

int64_t vci_fs_avail_bytes_native(const char *path, size_t path_len) {
    (void)path;
    (void)path_len;
    return -1;
}

int64_t vci_fs_total_bytes_native(const char *path, size_t path_len) {
    (void)path;
    (void)path_len;
    return -1;
}

#endif
