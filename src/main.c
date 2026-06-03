#include "pmv.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <kvm.h>
#include <errno.h>

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

void export_json_manual(ProcessInfo *processes, int count, const char *filename) {
    FILE *f = stdout;
    if (filename != NULL) {
        f = fopen(filename, "w");
        if (!f) return;
    }
    fputs("[\n", f);
    for (int i = 0; i < count; i++) {
        fprintf(f, "  {\n");
        fprintf(f, "    \"pid\": %d,\n", processes[i].pid);
        fprintf(f, "    \"ppid\": %d,\n", processes[i].ppid);
        fprintf(f, "    \"name\": \"%s\",\n", processes[i].name);
        fprintf(f, "    \"ppname\": \"%s\",\n", processes[i].ppname);
        fprintf(f, "    \"pledge\": %s,\n", processes[i].has_pledge ? "true" : "false");
        fprintf(f, "    \"unveil\": %s,\n", processes[i].has_unveil ? "true" : "false");
        fprintf(f, "    \"wxneeded\": %s,\n", processes[i].wxneeded ? "true" : "false");
        fprintf(f, "    \"chrooted\": %s,\n", processes[i].chrooted ? "true" : "false");
        fprintf(f, "    \"context\": \"%s\",\n", (processes[i].pid < 100) ? "KERNEL" : "NATIVE");
        fprintf(f, "    \"score\": %d\n", processes[i].score);
        fprintf(f, "  }%s\n", (i + 1 < count) ? "," : "");
    }
    fputs("]\n", f);
    if (filename != NULL) fclose(f);
}

void export_csv(ProcessInfo *processes, int count, const char *filename) {
    FILE *f = stdout;
    if (filename != NULL) {
        f = fopen(filename, "w");
        if (!f) return;
    }
    fprintf(f, "pid,ppid,name,ppname,pledge,unveil,wxneeded,chrooted,context,score\n");
    for (int i = 0; i < count; i++) {
        fprintf(f, "%d,%d,%s,%s,%d,%d,%d,%d,%s,%d\n",
            processes[i].pid, processes[i].ppid, processes[i].name, processes[i].ppname,
            processes[i].has_pledge, processes[i].has_unveil,
            processes[i].wxneeded, processes[i].chrooted,
            (processes[i].pid < 100) ? "KERNEL" : "NATIVE",
            processes[i].score
        );
    }
    if (filename != NULL) fclose(f);
}

static const char *snapshot_path(void) {
    return SNAPSHOT_FILE;
}

static int save_snapshot(const ProcessInfo *plist, int count) {
    const char *path = snapshot_path();
    int fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW, 0644);
    if (fd == -1) return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); return -1; }
    for (int i = 0; i < count; i++) {
        fprintf(f, "%d|%s|%d|%d|%d\n",
            plist[i].pid, plist[i].name,
            plist[i].has_pledge, plist[i].has_unveil,
            plist[i].wxneeded);
    }
    fclose(f);
    return 0;
}

static ProcessInfo *load_snapshot(int *count) {
    const char *path = snapshot_path();
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
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
        arr[n].pid = atoi(tok);
        tok = strtok(NULL, "|\n");
        if (!tok) continue;
        strlcpy(arr[n].name, tok, sizeof(arr[n].name));
        tok = strtok(NULL, "|\n");
        if (!tok) continue;
        arr[n].has_pledge = atoi(tok);
        tok = strtok(NULL, "|\n");
        if (!tok) continue;
        arr[n].has_unveil = atoi(tok);
        tok = strtok(NULL, "|\n");
        if (!tok) continue;
        arr[n].wxneeded = atoi(tok);
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
            target_wx_pid = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--pid") == 0) {
            if (i + 1 >= argc || argv[i+1][0] == '-') errx(1, "PID required");
            target_pid = (pid_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--format") == 0) {
            if (i + 1 >= argc || argv[i+1][0] == '-') errx(1, "format required");
            if (strcmp(argv[i+1], "json") == 0) out_format = JSON;
            else if (strcmp(argv[i+1], "csv") == 0) out_format = CSV;
            i++;
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
        int idx = 0;
        for (int i = 0; i < count; i++) if (processes[i].pid == target_pid || processes[i].ppid == target_pid) display_list[idx++] = processes[i];
    }
    int oldp_count = 0;
    ProcessInfo *oldp = NULL;
    if (diff_mode) oldp = load_snapshot(&oldp_count);
    if (unveil("/dev", "r") == -1 || unveil("output.json", "rwc") == -1 || unveil("output.csv", "rwc") == -1 || unveil(SNAPSHOT_FILE, "rwc") == -1 || unveil("/usr/lib", "r") == -1 || unveil(NULL, NULL) == -1) err(1, "unveil");
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
            if ((i + 1) % 20 == 0 && (i + 1) < display_count) { getchar(); }
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
    if (target_pid > 0 && display_list) free(display_list);
    if (target_pid == 0) free(processes);
    return 0;
}
