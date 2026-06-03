#ifndef PMV_H
#define PMV_H

#include <sys/types.h>

typedef struct {
    pid_t pid;
    pid_t ppid;
    char name[64];
    char ppname[64];
    int has_pledge;
    int has_unveil;
    int wxneeded;
    int chrooted;
    int score;
} ProcessInfo;

ProcessInfo* get_all_processes(int *count);
int compute_security_score(const ProcessInfo *p);
void audit_process_memory(int pid);
void audit_self(void);

#endif
