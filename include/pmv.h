#ifndef PMV_H
#define PMV_H

#include <sys/types.h>
#include <stdio.h>
#include <stddef.h>

typedef struct {
    pid_t pid;
    pid_t ppid;
    char name[64];
    char ppname[64];
    int has_pledge;
    int has_unveil;
    int chrooted;
    int score;
} ProcessInfo;

ProcessInfo* get_all_processes(int *count);
int compute_security_score(const ProcessInfo *p);
int pmv_parse_int(const char *s, int *out);
void pmv_json_escape(FILE *f, const char *s);
void pmv_csv_field(FILE *f, const char *s);
int pmv_snapshot_encode(const char *in, char *out, size_t outsz);
int pmv_snapshot_decode(const char *in, char *out, size_t outsz);
void audit_process_memory(int pid);
void audit_self(void);

#endif
