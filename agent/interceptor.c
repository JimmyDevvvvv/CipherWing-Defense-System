#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>

// === DEBUG MODE ===
#define DEBUG 1

// === Original function pointers ===
static int (*original_open)(const char *pathname, int flags, ...) = NULL;
static FILE *(*original_fopen)(const char *pathname, const char *mode) = NULL;
static int (*original_execve)(const char *filename, char *const argv[], char *const envp[]) = NULL;

// === Init function ===
__attribute__((constructor)) void init() {
    original_open = dlsym(RTLD_NEXT, "open");
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    original_execve = dlsym(RTLD_NEXT, "execve");

    if (DEBUG) fprintf(stderr, "[DEBUG] Interceptor initialized.\n");
}

// === Malware scanner wrapper ===
int is_malicious(const char *filepath) {
    static int scanning = 0;
    if (scanning || getenv("CIPHERWING_NO_HOOK")) {
        if (DEBUG) fprintf(stderr, "[DEBUG] Skipping scan due to hook flag.\n");
        return 0;
    }

    scanning = 1;
    setenv("CIPHERWING_NO_HOOK", "1", 1);

    // === Resolve full absolute path
    char resolved[PATH_MAX];
    if (!realpath(filepath, resolved)) {
        scanning = 0;
        unsetenv("CIPHERWING_NO_HOOK");
        return 0;
    }

    // === Skip IPC pipe
    if (strstr(resolved, "/tmp/cipherwing_pipe")) {
        if (DEBUG) fprintf(stderr, "[DEBUG] Skipping IPC pipe scan.\n");
        scanning = 0;
        unsetenv("CIPHERWING_NO_HOOK");
        return 0;
    }

    if (DEBUG) fprintf(stderr, "[DEBUG] Scanning: %s\n", resolved);

    // === Run Python scanner
    char cmd[5120];
    snprintf(cmd, sizeof(cmd),
        "env -u LD_PRELOAD python3 /home/jimbo/Desktop/Projects/cipherwing/ML_scanner/scanner.py '%s' > /tmp/scan_result.txt 2>/dev/null",
        resolved);
    system(cmd);

    unsetenv("CIPHERWING_NO_HOOK");
    scanning = 0;

    // === Check result
    FILE *fp = original_fopen("/tmp/scan_result.txt", "r");
    if (!fp) return 0;

    int malicious = 0;
    char line[1024];

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "'is_malware':") || strstr(line, "\"is_malware\":")) {
            if (strstr(line, "True") || strstr(line, "true"))
                malicious = 1;
        }
    }

    fclose(fp);

    if (malicious) {
        fprintf(stderr, "[BLOCKED] Malicious file access detected: %s\n", resolved);

        // === IPC pipe send
        FILE *pipe = original_fopen("/tmp/cipherwing_pipe", "w");
        if (pipe) {
            fprintf(pipe, "%s\n", resolved);
            fclose(pipe);
        } else if (DEBUG) {
            fprintf(stderr, "[DEBUG] Failed to open IPC pipe.\n");
        }
    }

    return malicious;
}

// === Hooked open() ===
int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    if (is_malicious(pathname)) {
        errno = EACCES;
        return -1;
    }

    return (flags & O_CREAT) ? original_open(pathname, flags, mode)
                             : original_open(pathname, flags);
}

// === Hooked fopen() ===
FILE *fopen(const char *pathname, const char *mode) {
    if (getenv("CIPHERWING_NO_HOOK")) {
        return original_fopen(pathname, mode);
    }

    if (is_malicious(pathname)) {
        if (DEBUG) fprintf(stderr, "[DEBUG] fopen blocked malicious file: %s\n", pathname);
        errno = EACCES;
        return NULL;
    }

    return original_fopen(pathname, mode);
}

// === Hooked execve() ===
int execve(const char *filename, char *const argv[], char *const envp[]) {
    if (!filename) return -1;

    if (is_malicious(filename)) {
        errno = EACCES;
        return -1;
    }

    return original_execve(filename, argv, envp);
}
