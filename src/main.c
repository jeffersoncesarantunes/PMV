#include "pmv.h"
#include "colors.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <kvm.h>
#include <errno.h>
#include <ctype.h>
#include <openssl/sha.h>

#define PMV_VERSION "development"

#define SNAPSHOT_FILE ".pmv_snapshot"
#define SNAPSHOT_HASH_FILE ".pmv_snapshot.sha256"

enum OutputFormat { NONE, JSON, CSV };
int quiet_mode = 0;
int no_pager = 0;
static char *g_snapshot_file = NULL;
static char *g_output_file = NULL;

static const char *score_color(int score) {
    if (score >= 4) return CLR_GREEN;
    if (score >= 1) return CLR_YELLOW;
    return CLR_RED;
}

void print_separator(void) {
    if (quiet_mode) return;
    printf("----------------------------------------------------------------------------------------------------\n");
}

void print_header(void) {
    if (quiet_mode) return;
    printf("%s%s==========================================================================================\n", CLR_BOLD, CLR_CYAN);
    printf("  PMV - Process Mitigation Viewer\n");
    printf("==========================================================================================\n%s", CLR_RESET);
}

static void sanitize_terminal_output(char *dst, const char *src, size_t dstsz) {
    size_t j = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p && j + 1 < dstsz; p++) {
        unsigned char c = *p;
        if (c == '\x1b') {
            while (*p && *p != 'm') p++;
            continue;
        }
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') continue;
        dst[j++] = (char)c;
    }
    dst[j] = '\0';
}

static int snapshot_sha256_file(const char *path, char *hash_out, size_t hash_outsz) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) return -1;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    unsigned char buf[8192];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0)
        SHA256_Update(&ctx, buf, (size_t)n);
    close(fd);
    if (n < 0) return -1;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(digest, &ctx);
    for (int i = 0; i < SHA256_DIGEST_LENGTH && (size_t)(i * 2 + 1) < hash_outsz; i++)
        snprintf(hash_out + i * 2, hash_outsz - (size_t)(i * 2), "%02x", digest[i]);
    return 0;
}

static int save_snapshot_with_hash(const ProcessInfo *plist, int count) {
    const char *path = g_snapshot_file ? g_snapshot_file : SNAPSHOT_FILE;
    char tmp_path[512];
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s.XXXXXX", path);
    if (n < 0 || (size_t)n >= sizeof(tmp_path)) return -1;
    int fd = mkstemp(tmp_path);
    if (fd == -1) return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmp_path); return -1; }
    for (int i = 0; i < count; i++) {
        char encoded[256];
        if (pmv_snapshot_encode(plist[i].name, encoded, sizeof(encoded)) != 0) {
            fclose(f);
            unlink(tmp_path);
            return -1;
        }
        fprintf(f, "%d|%s|%d|%d|%d\n",
            plist[i].pid, encoded,
            plist[i].has_pledge, plist[i].has_unveil,
            plist[i].chrooted);
    }
    char hash[SHA256_DIGEST_LENGTH * 2 + 1] = {0};
    fclose(f);
    if (snapshot_sha256_file(tmp_path, hash, sizeof(hash)) != 0) {
        unlink(tmp_path);
        return -1;
    }
    char hash_path[512];
    snprintf(hash_path, sizeof(hash_path), "%s.sha256", path);
    int hfd = open(hash_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (hfd == -1) { unlink(tmp_path); return -1; }
    FILE *hf = fdopen(hfd, "w");
    if (!hf) { close(hfd); unlink(tmp_path); unlink(hash_path); return -1; }
    fprintf(hf, "%s  %s\n", hash, path);
    if (fclose(hf) != 0) { unlink(tmp_path); unlink(hash_path); return -1; }
    if (rename(tmp_path, path) == -1) { unlink(tmp_path); unlink(hash_path); return -1; }
    return 0;
}

static ProcessInfo *load_snapshot_with_hash(int *count) {
    const char *path = g_snapshot_file ? g_snapshot_file : SNAPSHOT_FILE;
    char hash_path[512];
    snprintf(hash_path, sizeof(hash_path), "%s.sha256", path);
    char expected_hash[SHA256_DIGEST_LENGTH * 2 + 1] = {0};
    int hfd = open(hash_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (hfd != -1) {
        FILE *hf = fdopen(hfd, "r");
        if (hf) {
            char line[512];
            if (fgets(line, sizeof(line), hf)) {
                char *sp = strchr(line, ' ');
                if (sp) {
                    size_t len = (size_t)(sp - line);
                    if (len < sizeof(expected_hash)) {
                        memcpy(expected_hash, line, len);
                        expected_hash[len] = '\0';
                    }
                }
            }
            fclose(hf);
        }
    } else {
        warnx("warning: no snapshot hash file found; snapshot integrity unverified");
    }
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd == -1) return NULL;
    FILE *f = fdopen(fd, "r");
    if (!f) { close(fd); return NULL; }
    int cap = 512;
    ProcessInfo *arr = calloc(cap, sizeof(ProcessInfo));
    if (!arr) { fclose(f); return NULL; }
    int n = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (n >= cap) {
            cap *= 2;
            ProcessInfo *tmp = reallocarray(arr, cap, sizeof(ProcessInfo));
            if (!tmp) break;
            arr = tmp;
        }
        char *tok = strtok(line, "|\n");
        if (!tok) continue;
        if (pmv_parse_int(tok, &arr[n].pid) != 0) continue;
        tok = strtok(NULL, "|\n");
        if (!tok) continue;
        if (pmv_snapshot_decode(tok, arr[n].name, sizeof(arr[n].name)) != 0) continue;
        tok = strtok(NULL, "|\n");
        if (!tok) continue;
        int val;
        if (pmv_parse_int(tok, &val) != 0) continue;
        arr[n].has_pledge = val;
        tok = strtok(NULL, "|\n");
        if (!tok) continue;
        if (pmv_parse_int(tok, &val) != 0) continue;
        arr[n].has_unveil = val;
        tok = strtok(NULL, "|\n");
        if (!tok) continue;
        if (pmv_parse_int(tok, &val) != 0) continue;
        arr[n].chrooted = val;
        n++;
    }
    fclose(f);
    if (expected_hash[0]) {
        char actual_hash[SHA256_DIGEST_LENGTH * 2 + 1] = {0};
        if (snapshot_sha256_file(path, actual_hash, sizeof(actual_hash)) == 0) {
            if (strcmp(expected_hash, actual_hash) != 0) {
                warnx("warning: snapshot hash mismatch; file may have been tampered");
            }
        }
    }
    *count = n;
    return arr;
}

static void export_json_manual(const ProcessInfo *processes, int count, const char *filename) {
    FILE *f = stdout;
    int needs_close = 0;
    if (filename != NULL) {
        int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
        if (fd == -1) { warn("cannot open %s", filename); return; }
        f = fdopen(fd, "w");
        if (!f) { close(fd); warn("cannot fdopen %s", filename); return; }
        needs_close = 1;
    }
    fputs("[\n", f);
    for (int i = 0; i < count; i++) {
        fprintf(f, "  {\n");
        fprintf(f, "    \"pid\": %d,\n", processes[i].pid);
        fprintf(f, "    \"ppid\": %d,\n", processes[i].ppid);
        fprintf(f, "    \"name\": ");
        pmv_json_escape(f, processes[i].name);
        fprintf(f, ",\n");
        fprintf(f, "    \"ppname\": ");
        pmv_json_escape(f, processes[i].ppname);
        fprintf(f, ",\n");
        fprintf(f, "    \"pledge\": %s,\n", processes[i].has_pledge ? "true" : "false");
        fprintf(f, "    \"unveil\": %s,\n", processes[i].has_unveil ? "true" : "false");
        fprintf(f, "    \"chrooted\": %s,\n", processes[i].chrooted ? "true" : "false");
        fprintf(f, "    \"context\": \"%s\",\n", (processes[i].pid < 100) ? "KERNEL" : "NATIVE");
        fprintf(f, "    \"score\": %d\n", processes[i].score);
        fprintf(f, "  }%s\n", (i + 1 < count) ? "," : "");
    }
    fputs("]\n", f);
    if (needs_close && fclose(f) != 0) {
        fprintf(stderr, "Warning: JSON write may be incomplete\n");
    }
}

static void export_csv(const ProcessInfo *processes, int count, const char *filename) {
    FILE *f = stdout;
    int needs_close = 0;
    if (filename != NULL) {
        int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
        if (fd == -1) { warn("cannot open %s", filename); return; }
        f = fdopen(fd, "w");
        if (!f) { close(fd); warn("cannot fdopen %s", filename); return; }
        needs_close = 1;
    }
    fprintf(f, "pid,ppid,name,ppname,pledge,unveil,chrooted,context,score\n");
    for (int i = 0; i < count; i++) {
        fprintf(f, "%d,%d,", processes[i].pid, processes[i].ppid);
        pmv_csv_field(f, processes[i].name);
        fprintf(f, ",");
        pmv_csv_field(f, processes[i].ppname);
        fprintf(f, ",%d,%d,%d,%s,%d\n",
            processes[i].has_pledge, processes[i].has_unveil,
            processes[i].chrooted,
            (processes[i].pid < 100) ? "KERNEL" : "NATIVE",
            processes[i].score
        );
    }
    if (needs_close && fclose(f) != 0) {
        fprintf(stderr, "Warning: CSV write may be incomplete\n");
    }
}

static const char *snapshot_path(void) {
    return g_snapshot_file ? g_snapshot_file : SNAPSHOT_FILE;
}

static int save_snapshot(const ProcessInfo *plist, int count) {
    return save_snapshot_with_hash(plist, count);
}

static ProcessInfo *load_snapshot(int *count) {
    return load_snapshot_with_hash(count);
}

static void print_diff(const ProcessInfo *oldp, int oldc, const ProcessInfo *newp, int newc) {
    int changes = 0;
    printf("\n%s[+] CHANGES FROM LAST SNAPSHOT\n%s", BOLD, RESET);
    printf("%-6s  %-7s %-7s %-7s  %s\n", "PID", "PLEDGE", "UNVEIL", "CHROOT", "PROCESS / NOTE");
    for (int i = 0; i < newc; i++) {
        int found = 0;
        for (int j = 0; j < oldc; j++) {
            if (newp[i].pid == oldp[j].pid) {
                found = 1;
                if (newp[i].has_pledge != oldp[j].has_pledge ||
                    newp[i].has_unveil != oldp[j].has_unveil ||
                    newp[i].chrooted  != oldp[j].chrooted) {
                    changes++;
                    printf("~ %-6d  ", newp[i].pid);
                    printf("%s=>%s ", oldp[j].has_pledge ? "PRESENT" : "NONE    ", newp[i].has_pledge ? "PRESENT" : "NONE");
                    printf("%s=>%s ", oldp[j].has_unveil ? "PRESENT" : "NONE    ", newp[i].has_unveil ? "PRESENT" : "NONE");
                    printf("%s=>%s  ", oldp[j].chrooted ? "CHROOT" : "no    ", newp[i].chrooted ? "CHROOT" : "no    ");
                    printf("%s\n", newp[i].name);
                }
                break;
            }
        }
        if (!found) {
            changes++;
            printf("+ %-6d  %-7s %-7s %-7s  %s (new)\n", newp[i].pid, newp[i].has_pledge ? "PRESENT" : "NONE", newp[i].has_unveil ? "PRESENT" : "NONE", newp[i].chrooted ? "CHROOT" : "no", newp[i].name);
        }
    }
    for (int i = 0; i < oldc; i++) {
        int found = 0;
        for (int j = 0; j < newc; j++) {
            if (oldp[i].pid == newp[j].pid) { found = 1; break; }
        }
        if (!found) {
            changes++;
            printf("- %-6d  %-7s %-7s %-7s  %s (exited)\n", oldp[i].pid, oldp[i].has_pledge ? "PRESENT" : "NONE", oldp[i].has_unveil ? "PRESENT" : "NONE", oldp[i].chrooted ? "CHROOT" : "no", oldp[i].name);
        }
    }
    if (changes == 0) printf("  (no changes)\n");
}

static void usage(void) {
    fprintf(stderr, "Usage: pmv [options]\n\nOptions:\n  -h, --help           Show help\n  --version            Show version\n  -q, --quiet          Suppress output\n  --no-pager           Disable interactive paging\n  --pid <PID>          Filter PID\n  --format <json|csv>  Export\n  --output <file>      Output file for json/csv\n  --diff               Compare snapshot\n  --scan-wx <PID>      Scan memory\n  --snapshot-file <f>  Snapshot file path (default: .pmv_snapshot)\n");
}

int main(int argc, char *argv[]) {
    setprogname(argv[0]);
    enum OutputFormat out_format = NONE;
    int target_wx_pid = 0, diff_mode = 0;
    pid_t target_pid = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) { usage(); return 0; }
        else if (strcmp(argv[i], "--version") == 0) { puts("pmv (development build)"); return 0; }
        else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) { quiet_mode = 1; }
        else if (strcmp(argv[i], "--no-pager") == 0) { no_pager = 1; }
        else if (strcmp(argv[i], "--diff") == 0) { diff_mode = 1; }
        else if (strcmp(argv[i], "--scan-wx") == 0) {
            if (i + 1 >= argc || argv[i+1][0] == '-') errx(1, "PID required");
            if (pmv_parse_int(argv[++i], &target_wx_pid) != 0) errx(1, "Invalid PID");
        } else if (strcmp(argv[i], "--pid") == 0) {
            if (i + 1 >= argc || argv[i+1][0] == '-') errx(1, "PID required");
            int parsed;
            if (pmv_parse_int(argv[++i], &parsed) != 0) errx(1, "Invalid PID");
            target_pid = (pid_t)parsed;
        } else if (strcmp(argv[i], "--format") == 0) {
            if (i + 1 >= argc || argv[i+1][0] == '-') errx(1, "format required");
            i++;
            char fmt_lower[16];
            size_t flen = strlen(argv[i]);
            if (flen >= sizeof(fmt_lower)) errx(1, "Invalid format");
            for (size_t j = 0; j < flen; j++) fmt_lower[j] = (char)tolower((unsigned char)argv[i][j]);
            fmt_lower[flen] = '\0';
            if (strcmp(fmt_lower, "json") == 0) out_format = JSON;
            else if (strcmp(fmt_lower, "csv") == 0) out_format = CSV;
            else errx(1, "Unknown format: %s (use json or csv)", argv[i]);
        } else if (strcmp(argv[i], "--output") == 0) {
            if (i + 1 >= argc || argv[i+1][0] == '-') errx(1, "output file required");
            g_output_file = strdup(argv[++i]);
        } else if (strcmp(argv[i], "--snapshot-file") == 0) {
            if (i + 1 >= argc || argv[i+1][0] == '-') errx(1, "snapshot file required");
            g_snapshot_file = strdup(argv[++i]);
        }
    }
    if (target_wx_pid > 0) { audit_process_memory(target_wx_pid); return 0; }
    if (unveil(".", "rwc") == -1 || unveil("/dev", "r") == -1 || unveil(NULL, NULL) == -1) err(1, "unveil");
    if (out_format == NONE) { print_header(); }
    int count = 0;
    ProcessInfo *processes = get_all_processes(&count);
    if (!processes) errx(1, "Could not fetch processes");
    if (pledge("stdio rpath wpath cpath ps vminfo unveil", NULL) == -1) err(1, "pledge");
    int display_count = count;
    ProcessInfo *display_list = processes;
    if (target_pid > 0) {
        display_count = 0;
        for (int i = 0; i < count; i++) if (processes[i].pid == target_pid || processes[i].ppid == target_pid) display_count++;
        if (display_count > 0) {
            display_list = calloc((size_t)display_count, sizeof(ProcessInfo));
            if (!display_list) err(1, "calloc");
            int idx = 0;
            for (int i = 0; i < count; i++)
                if (processes[i].pid == target_pid || processes[i].ppid == target_pid)
                    display_list[idx++] = processes[i];
        } else {
            display_list = NULL;
        }
    }
    int oldp_count = 0;
    ProcessInfo *oldp = NULL;
    if (diff_mode) oldp = load_snapshot(&oldp_count);
    if (out_format == NONE && !quiet_mode) {
        if (target_pid > 0) printf("\n%s[+] Filtered PID %d\n%s", BOLD, target_pid, RESET);
        printf("\n%s%-8s %-6s %-22s %-22s %-7s %-7s %-7s %-6s\n%s", BOLD, "PID", "PPID", "PROCESS", "PARENT", "PLEDGE", "UNVEIL", "CHROOT", "SCORE", RESET);
        print_separator();
    }
    int pledged_count = 0, unveiled_count = 0, chroot_count = 0;
    for (int i = 0; i < display_count; i++) {
        ProcessInfo *p = &display_list[i];
        if (p->has_pledge) pledged_count++;
        if (p->has_unveil) unveiled_count++;
        if (p->chrooted) chroot_count++;
        if (out_format == NONE && !quiet_mode) {
            char safe_name[64], safe_ppname[64];
            sanitize_terminal_output(safe_name, p->name, sizeof(safe_name));
            sanitize_terminal_output(safe_ppname, p->ppname, sizeof(safe_ppname));
            const char *ctx_color = (p->pid < 100) ? CLR_MAGENTA : CLR_BLUE;
            printf("%s%-8d%s %-6d %-22.22s %-22.22s %s%-7s%s %s%-7s%s %s%-7s%s %s%-6d%s\n",
                ctx_color, p->pid, CLR_RESET,
                p->ppid, safe_name, safe_ppname,
                p->has_pledge ? CLR_GREEN : CLR_RED, p->has_pledge ? "PRESENT" : "NONE", CLR_RESET,
                p->has_unveil ? CLR_GREEN : CLR_YELLOW, p->has_unveil ? "PRESENT" : "NONE", CLR_RESET,
                p->chrooted ? CLR_GREEN : CLR_YELLOW, p->chrooted ? "CHROOT" : "no", CLR_RESET,
                score_color(p->score), p->score, CLR_RESET);
            if ((i + 1) % 20 == 0 && (i + 1) < display_count && !no_pager && isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) { getchar(); }
        }
    }
    if (out_format == NONE && diff_mode && oldp) { print_diff(oldp, oldp_count, display_list, display_count); free(oldp); }
    if (out_format == NONE && !quiet_mode) {
        print_separator();
        printf("\n%s[+] MITIGATION SUMMARY\n%s    [#] Total: %d\n    [#] Pledge: %d\n    [#] Unveil: %d\n    [#] Chroot: %d\n", BOLD, RESET, display_count, pledged_count, unveiled_count, chroot_count);
    }
    const char *out_json = (out_format == JSON) ? (g_output_file ? g_output_file : (quiet_mode ? "output.json" : NULL)) : NULL;
    const char *out_csv = (out_format == CSV) ? (g_output_file ? g_output_file : (quiet_mode ? "output.csv" : NULL)) : NULL;
    if (out_format == JSON) export_json_manual(display_list, display_count, out_json);
    if (out_format == CSV) export_csv(display_list, display_count, out_csv);
    if (!diff_mode && save_snapshot(display_list, display_count) == -1 && !quiet_mode && out_format == NONE) warn("save_snapshot");
    free(processes);
    if (target_pid > 0 && display_list) free(display_list);
    free(g_snapshot_file);
    free(g_output_file);
    return 0;
}
