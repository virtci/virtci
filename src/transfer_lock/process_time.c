#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <stdio.h>

#if defined(__APPLE__)
#include <sys/proc_info.h>
#include <libproc.h>

bool get_process_start_time_native(uint32_t pid, uint64_t *out_start_time) {
    struct proc_bsdinfo info;
    int ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (ret <= 0) {
        return false;
    }
    *out_start_time = info.pbi_start_tvsec * 1000000ULL + info.pbi_start_tvusec;
    return true;
}

// macOS: start_time is microseconds since epoch
uint64_t start_time_to_unix_secs(uint64_t start_time) {
    return start_time / 1000000ULL;
}

#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

bool get_process_start_time_native(uint32_t pid, uint64_t *out_start_time) {
    HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (handle == NULL) {
        return false;
    }

    FILETIME creation_time, exit_time, kernel_time, user_time;
    BOOL success = GetProcessTimes(handle, &creation_time, &exit_time, &kernel_time, &user_time);
    CloseHandle(handle);

    if (!success) {
        return false;
    }

    *out_start_time = ((uint64_t)creation_time.dwHighDateTime << 32) | creation_time.dwLowDateTime;
    return true;
}


uint64_t start_time_to_unix_secs(uint64_t start_time) {
    // start_time is FILETIME (100-nanosecond intervals since Jan 1, 1601) on windows for some reason
    // 1601 to 1970 in 100-nanosecond intervals
    const uint64_t EPOCH_DIFF = 116444736000000000ULL;
    if (start_time < EPOCH_DIFF) {
        return 0;
    }
    return (start_time - EPOCH_DIFF) / 10000000ULL;
}

#elif defined(__linux__)
#include <string.h>
#include <unistd.h>

static uint64_t get_boot_time(void) {
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return 0;

    char line[256];
    uint64_t btime = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "btime %llu", &btime) == 1) {
            break;
        }
    }
    fclose(f);
    return btime;
}

bool get_process_start_time_native(uint32_t pid, uint64_t *out_start_time) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/stat", pid);

    FILE *f = fopen(path, "r");
    if (!f) {
        return false;
    }

    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);

    if (n == 0) {
        return false;
    }
    buf[n] = '\0';

    char *after_comm = strrchr(buf, ')');
    if (!after_comm) {
        return false;
    }
    after_comm++;

    uint64_t starttime;
    int fields_parsed = sscanf(after_comm,
        " %*c"      // state
        " %*d"      // ppid
        " %*d"      // pgrp
        " %*d"      // session
        " %*d"      // tty_nr
        " %*d"      // tpgid
        " %*u"      // flags
        " %*u"      // minflt
        " %*u"      // cminflt
        " %*u"      // majflt
        " %*u"      // cmajflt
        " %*u"      // utime
        " %*u"      // stime
        " %*d"      // cutime
        " %*d"      // cstime
        " %*d"      // priority
        " %*d"      // nice
        " %*d"      // num_threads
        " %*d"      // itrealvalue
        " %llu",    // starttime
        &starttime);

    if (fields_parsed != 1) {
        return false;
    }

    *out_start_time = starttime;
    return true;
}

// Linux: start_time is clock ticks since boot
uint64_t start_time_to_unix_secs(uint64_t start_time) {
    long ticks_per_sec = sysconf(_SC_CLK_TCK);
    if (ticks_per_sec <= 0) {
        ticks_per_sec = 100; // fallback
    }
    uint64_t boot_time = get_boot_time();
    return boot_time + (start_time / (uint64_t)ticks_per_sec);
}

#else
#error "Unsupported platform"
#endif

// `buf` should be at least 32 bytes
void format_unix_time_local(uint64_t unix_secs, char *buf, size_t buf_size) {
    time_t t = (time_t)unix_secs;
    struct tm local_tm;

#if defined(_WIN32)
    localtime_s(&local_tm, &t);
#else
    localtime_r(&t, &local_tm);
#endif

    strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", &local_tm);
}
