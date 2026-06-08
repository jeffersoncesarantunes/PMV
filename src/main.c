#include "pmv.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <kvm.h>
#include <errno.h>
#include <ctype.h>

#define RED    "\x1b[31m"
#define GRN    "\x1b[32m"
#define YEL    "\x1b[33m"
#define BLU    "\x1b[34m"
#define MAG    "\x1b[35m"
#define CYN    "\x1b[36m"
#define BOLD   "\x1b[1m"
#define RESET  "\x1b[0m"

#define SNAPSHOT_FILE ".pmv_snapshot"

enum OutputFormat { NONE, JSON, CSV };
int quiet_mode = 0;

static const char *score_color(int score) {
    if (score >= 4) return GRN;
    if (score >= 1) return YEL;
    return RED;
}

void print_separator(void) {
    if (quiet_mode) return;
    printf("----------------------------------------------------------------------------------------------------\n");
}

void print_header(void) {
    if (quiet_mode) return;
    printf(BOLD CYN "==========================================================================================\n");
    printf("  PMV - Process Mitigation Viewer\n");
    printf("==========================================================================================\n" RESET);
}

static void json_escape(FILE *f, const char *s) {
    fputc('"', f);
    while (*s) {
        switch (*s) {
            case '"':  fprintf(f, "\\\""); break;
            case '\\': fprintf(f, "\\\\"); break;
            case '\n': fprintf(f, "\\n");  break;
            case '\r': fprintf(f, "\\r");  break;
            case '\t': fprintf(f, "\\t");  break;
            default:   fputc(*s, f);       break;
        }
        s++;
    }
    fputc('"', f);
}

static void csv_field(FILE *f, const char *s) {
    int needs_quote = 0;
    for (const char *p = s; *p; p++) {
        if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') {
            needs_quote = 1;
            break;
        }
    }
    if (needs_quote) {
        fputc('"', f);
        while (*s) {
            if (*s == '"') fprintf(f, "\"\"");
            else fputc(*s, f);
            s++;
        }
        fputc('"', f);
    } else {
        fprintf(f, "%s", s);
    }
}

void export_json_manual(ProcessInfo *processes, int count, const char *filename) {
    FILE *f = stdout;
    int needs_close = 0;
    if (filename != NULL) {
        f = fopen(filename, "w");
        if (!f) return;
        needs_close = 1;
    }
    fputs("[\n", f);
    for (int i = 0; i < count; i++) {
        fprintf(f, "  {\n");
        fprintf(f, "    \"pid\": %d,\n", processes[i].pid);
        fprintf(f, "    \"ppid\": %d,\n", processes[i].ppid);
        fprintf(f, "    \"name\": ");
        json_escape(f, processes[i].name);
        fprintf(f, ",\n");
        fprintf(f, "    \"ppname\": ");
        json_escape(f, processes[i].ppname);
        fprintf(f, ",\n");
        fprintf(f, "    \"pledge\": %s,\n", processes[i].has_pledge ? "true" : "false");
        fprintf(f, "    \"unveil\": %s,\n", processes[i].has_unveil ? "true" : "false");
        fprintf(f, "    \"wxneeded\": %s,\n", processes[i].wxneeded ? "true" : "false");
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

void export_csv(ProcessInfo *processes, int count, const char *filename) {
    FILE *f = stdout;
    int needs_close = 0;
    if (filename != NULL) {
        f = fopen(filename, "w");
        if (!f) return;
        needs_close = 1;
    }
    fprintf(f, "pid,ppid,name,ppname,pledge,unveil,wxneeded,chrooted,context,score\n");
    for (int i = 0; i < count; i++) {
        fprintf(f, "%d,%d,", processes[i].pid, processes[i].ppid);
        csv_field(f, processes[i].name);
        fprintf(f, ",");
        csv_field(f, processes[i].ppname);
        fprintf(f, ",%d,%d,%d,%d,%s,%d\n",
            processes[i].has_pledge, processes[i].has_unveil,
            processes[i].wxneeded, processes[i].chrooted,
            (processes[i].pid < 100) ? "KERNEL" : "NATIVE",
            processes[i].score
        );
    }
    if (needs_close && fclose(f) != 0) {
        fprintf(stderr, "Warning: CSV write may be incomplete\n");
    }
}

static const char *snapshot_path(void) {
    return SNAPSHOT_FILE;
}

static int save_snapshot(const ProcessInfo *plist, int count) {
    const char *path = snapshot_path();
    int fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd == -1) return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); return -1; }
    for (int i = 0; i < count; i++) {
        fprintf(f, "%d|%s|%d|%d|%d\n",
            plist[i].pid, plist[i].name,
            plist[i].has_pledge, plist[i].has_unveil,
            plist[i].wxneeded);
    }
    if (fclose(f) != 0) return -1;
    return 0;
}

static int parse_int(const char *s, int *out) {
    char *end;
    long v = strtol(s, &end, 10);
    if (*end != '\0' || v < 0 || v > 999999) return -1;
    *out = (int)v;
    return 0;
}

static ProcessInfo *load_snapshot(int *count) {
    const char *path = snapshot_path();
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
        if (parse_int(tok, &arr[n].pid) != 0) continue;
        tok = strtok(NULL, "|\n");
        if (!tok) continue;
        strlcpy(arr[n].name, tok, sizeof(arr[n].name));
        tok = strtok(NULL, "|\n");
        if (!tok) continue;
        int val;
        if (parse_int(tok, &val) != 0) continue;
        arr[n].has_pledge = val;
        tok = strtok(NULL, "|\n");
        if (!tok) continue;
        if (parse_int(tok, &val) != 0) continue;
        arr[n].has_unveil = val;
        tok = strtok(NULL, "|\n");
        if (!tok) continue;
        if (parse_int(tok, &val) != 0) continue;
        arr[n].wxneeded = val;
        n++;
    }
    fclose(f);
    *count = n;
    return arr;
}

static void print_diff(const ProcessInfo *oldp, int oldc, const ProcessInfo *newp, int newc) {
    int changes = 0;
    printf("\n" BOLD "[+] CHANGES FROM LAST SNAPSHOT\n" RESET);
    printf("%-6s  %-7s %-7s %-7s  %s\n", "PID", "PLEDGE", "UNVEIL", "W^X", "PROCESS / NOTE");
    for (int i = 0; i < newc; i++) {
        int found = 0;
        for (int j = 0; j < oldc; j++) {
            if (newp[i].pid == oldp[j].pid) {
                found = 1;
                if (newp[i].has_pledge != oldp[j].has_pledge ||
                    newp[i].has_unveil != oldp[j].has_unveil ||
                    newp[i].wxneeded  != oldp[j].wxneeded) {
                    changes++;
                    printf("~ %-6d  ", newp[i].pid);
                    printf("%s=>%s ", oldp[j].has_pledge ? "PRESENT" : "NONE    ", newp[i].has_pledge ? "PRESENT" : "NONE");
                    printf("%s=>%s ", oldp[j].has_unveil ? "PRESENT" : "NONE    ", newp[i].has_unveil ? "PRESENT" : "NONE");
                    printf("%s=>%s  ", oldp[j].wxneeded ? "W^X" : "ok ", newp[i].wxneeded ? "W^X" : "ok ");
                    printf("%s\n", newp[i].name);
                }
                break;
            }
        }
        if (!found) {
            changes++;
            printf("+ %-6d  %-7s %-7s %-7s  %s (new)\n", newp[i].pid, newp[i].has_pledge ? "PRESENT" : "NONE", newp[i].has_unveil ? "PRESENT" : "NONE", newp[i].wxneeded ? "W^X" : "ok", newp[i].name);
        }
    }
    for (int i = 0; i < oldc; i++) {
        int found = 0;
        for (int j = 0; j < newc; j++) {
            if (oldp[i].pid == newp[j].pid) { found = 1; break; }
        }
        if (!found) {
            changes++;
            printf("- %-6d  %-7s %-7s %-7s  %s (exited)\n", oldp[i].pid, oldp[i].has_pledge ? "PRESENT" : "NONE", oldp[i].has_unveil ? "PRESENT" : "NONE", oldp[i].wxneeded ? "W^X" : "ok", oldp[i].name);
        }
    }
    if (changes == 0) printf("  (no changes)\n");
}

static void usage(void) {
    fprintf(stderr, "Usage: pmv [options]\n\nOptions:\n  -h, --help           Show help\n  -q, --quiet          Suppress output\n  --pid <PID>          Filter PID\n  --format <json|csv>  Export\n  --diff               Compare snapshot\n  --scan-wx <PID>      Scan memory\n");
}

int main(int argc, char *argv[]) {
    enum OutputFormat out_format = NONE;
    int target_wx_pid = 0, diff_mode = 0;
    pid_t target_pid = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) { usage(); return 0; }
        else if (strcmp(argv[i], "--quiet") == 0 || strcmp(argv[i], "-q") == 0) { quiet_mode = 1; }
        else if (strcmp(argv[i], "--diff") == 0) { diff_mode = 1; }
        else if (strcmp(argv[i], "--scan-wx") == 0) {
            if (i + 1 >= argc || argv[i+1][0] == '-') errx(1, "PID required");
            if (parse_int(argv[++i], &target_wx_pid) != 0) errx(1, "Invalid PID");
        } else if (strcmp(argv[i], "--pid") == 0) {
            if (i + 1 >= argc || argv[i+1][0] == '-') errx(1, "PID required");
            int parsed;
            if (parse_int(argv[++i], &parsed) != 0) errx(1, "Invalid PID");
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
        }
    }
    if (target_wx_pid > 0) { audit_process_memory(target_wx_pid); return 0; }
    if (out_format == NONE) { print_header(); if (!quiet_mode) audit_self(); }
    int count = 0;
    ProcessInfo *processes = get_all_processes(&count);
    if (!processes) errx(1, "Could not fetch processes");
    int display_count = count;
    ProcessInfo *display_list = processes;
    if (target_pid > 0) {
        display_count = 0;
        for (int i = 0; i < count; i++) if (processes[i].pid == target_pid || processes[i].ppid == target_pid) display_count++;
        display_list = calloc(display_count, sizeof(ProcessInfo));
        if (!display_list) err(1, "calloc");
        int idx = 0;
        for (int i = 0; i < count; i++) if (processes[i].pid == target_pid || processes[i].ppid == target_pid) display_list[idx++] = processes[i];
    }
    int oldp_count = 0;
    ProcessInfo *oldp = NULL;
    if (diff_mode) oldp = load_snapshot(&oldp_count);
    if (unveil("/dev", "r") == -1 || unveil(NULL, NULL) == -1) err(1, "unveil");
    if (pledge("stdio rpath wpath cpath ps vminfo unveil", NULL) == -1) err(1, "pledge");
    if (out_format == NONE && !quiet_mode) {
        if (target_pid > 0) printf("\n" BOLD "[+] Filtered PID %d\n" RESET, target_pid);
        printf("\n" BOLD "%-8s %-6s %-22s %-22s %-7s %-7s %-7s %-6s\n" RESET, "PID", "PPID", "PROCESS", "PARENT", "PLEDGE", "UNVEIL", "W^X", "SCORE");
        print_separator();
    }
    int pledged_count = 0, unveiled_count = 0, chroot_count = 0, wx_count = 0, score_sum = 0, score_max = -999, score_min = 999;
    for (int i = 0; i < display_count; i++) {
        ProcessInfo *p = &display_list[i];
        if (p->has_pledge) pledged_count++; if (p->has_unveil) unveiled_count++; if (p->chrooted) chroot_count++; if (p->wxneeded) wx_count++;
        score_sum += p->score; if (p->score > score_max) score_max = p->score; if (p->score < score_min) score_min = p->score;
        if (out_format == NONE && !quiet_mode) {
            char *ctx_color = (p->pid < 100) ? MAG : BLU;
            printf("%s%-8d" RESET " %-6d %-22.22s %-22.22s %s%-7s" RESET " %s%-7s" RESET " %s%-7s" RESET " %s%-6d" RESET "\n", ctx_color, p->pid, p->ppid, p->name, p->ppname, p->has_pledge ? GRN : RED, p->has_pledge ? "PRESENT" : "NONE", p->has_unveil ? GRN : YEL, p->has_unveil ? "PRESENT" : "NONE", p->wxneeded ? RED : GRN, p->wxneeded ? "W^X" : "ok", score_color(p->score), p->score);
            if ((i + 1) % 20 == 0 && (i + 1) < display_count && isatty(STDIN_FILENO)) { getchar(); }
        }
    }
    if (out_format == NONE && diff_mode && oldp) { print_diff(oldp, oldp_count, display_list, display_count); free(oldp); }
    if (out_format == NONE && !quiet_mode) {
        print_separator();
        printf("\n" BOLD "[+] MITIGATION SUMMARY\n" RESET "    [#] Total: %d\n    [#] Pledge: %d\n    [#] Unveil: %d\n    [#] W^X Violations: %d\n", display_count, pledged_count, unveiled_count, wx_count);
    }
    if (out_format == JSON) export_json_manual(display_list, display_count, quiet_mode ? "output.json" : NULL);
    if (out_format == CSV) export_csv(display_list, display_count, quiet_mode ? "output.csv" : NULL);
    if (!diff_mode && save_snapshot(display_list, display_count) == -1 && !quiet_mode && out_format == NONE) warn("save_snapshot");
    free(processes);
    if (target_pid > 0 && display_list) free(display_list);
    return 0;
}
