#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/mman.h>
#include <kvm.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include "pmv.h"

#ifndef PS_WXNEEDED
#define PS_WXNEEDED 0x00040000
#endif

#ifndef PS_UNVEIL
#define PS_UNVEIL 0x01000000
#endif

#ifndef P_CHROOT
#define P_CHROOT 0x00004000
#endif

ProcessInfo* get_all_processes(int *count) {
    kvm_t *kd;
    char errbuf[_POSIX2_LINE_MAX];
    struct kinfo_proc *kp;
    int nprocs;

    kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, errbuf);
    if (kd == NULL) return NULL;

    kp = kvm_getprocs(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc), &nprocs);
    if (kp == NULL) {
        kvm_close(kd);
        return NULL;
    }

    ProcessInfo *list = calloc(nprocs, sizeof(ProcessInfo));
    if (!list) {
        kvm_close(kd);
        return NULL;
    }

    for (int i = 0; i < nprocs; i++) {
        list[i].pid = kp[i].p_pid;
        list[i].ppid = kp[i].p_ppid;
        strlcpy(list[i].name, kp[i].p_comm, sizeof(list[i].name));
        list[i].has_pledge = (kp[i].p_psflags & PS_PLEDGE) ? 1 : 0;
        list[i].has_unveil = (kp[i].p_psflags & PS_UNVEIL) ? 1 : 0;
        list[i].wxneeded = (kp[i].p_psflags & PS_WXNEEDED) ? 1 : 0;
        list[i].chrooted = (kp[i].p_flag & P_CHROOT) ? 1 : 0;
    }

    for (int i = 0; i < nprocs; i++) {
        list[i].ppname[0] = '\0';
        for (int j = 0; j < nprocs; j++) {
            if (list[j].pid == list[i].ppid) {
                strlcpy(list[i].ppname, list[j].name, sizeof(list[i].ppname));
                break;
            }
        }
        if (list[i].ppname[0] == '\0')
            snprintf(list[i].ppname, sizeof(list[i].ppname), "(kernel/init)");
    }

    for (int i = 0; i < nprocs; i++)
        list[i].score = compute_security_score(&list[i]);

    *count = nprocs;
    kvm_close(kd);
    return list;
}

int compute_security_score(const ProcessInfo *p) {
    int score = 0;

    if (p->has_pledge) score += 3;
    if (p->has_unveil) score += 2;
    if (p->chrooted)   score += 1;
    if (p->wxneeded)   score -= 2;

    return score;
}

void audit_process_memory(int pid) {
    int mib[4];
    struct kinfo_vmentry *vme = NULL;
    size_t size;
    int wx_count = 0, region_count = 0;

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_VMMAP;
    mib[3] = pid;

    if (sysctl(mib, 4, NULL, &size, NULL, 0) == -1) {
        if (errno == EINVAL) {
            printf("\n\x1b[33m[!] VMMAP sysctl failed for PID %d: KERN_PROC_VMMAP is restricted or not available on this kernel.\x1b[0m\n", pid);
        } else if (errno == EACCES || errno == EPERM) {
            fprintf(stderr, "[-] Permission denied for PID %d: %s\n    (KERN_PROC_VMMAP requires elevated privileges)\n", pid, strerror(errno));
        } else {
            fprintf(stderr, "[-] Kernel error for PID %d: %s\n", pid, strerror(errno));
        }
        return;
    }

    vme = malloc(size);
    if (!vme) {
        warn("malloc");
        return;
    }

    if (sysctl(mib, 4, vme, &size, NULL, 0) == -1) {
        warn("sysctl (KERN_PROC_VMMAP) for PID %d", pid);
        free(vme);
        return;
    }

    printf("\n[+] W^X Memory Scan for PID %d\n", pid);
    printf("    %-18s %-18s %-10s\n", "START ADDR", "END ADDR", "PROT");

    int nentries = size / sizeof(struct kinfo_vmentry);
    for (int i = 0; i < nentries; i++) {
        struct kinfo_vmentry *entry = &vme[i];

        if (entry->kve_start == 0 && entry->kve_end == 0) continue;
        region_count++;

        char prot_str[4] = "---";
        if (entry->kve_protection & PROT_READ)  prot_str[0] = 'r';
        if (entry->kve_protection & PROT_WRITE) prot_str[1] = 'w';
        if (entry->kve_protection & PROT_EXEC)  prot_str[2] = 'x';

        int is_wx = (entry->kve_protection & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC);
        if (is_wx) wx_count++;

        if (is_wx) {
            printf("    0x%016llx-0x%016llx \033[31m%s [VIOLATION]\033[0m\n", 
                   (unsigned long long)entry->kve_start, 
                   (unsigned long long)entry->kve_end, 
                   prot_str);
        } else {
            printf("    0x%016llx-0x%016llx %s\n", 
                   (unsigned long long)entry->kve_start, 
                   (unsigned long long)entry->kve_end, 
                   prot_str);
        }
    }

    printf("\n    [+] Scan complete: %d region(s) mapped, ", region_count);
    if (wx_count > 0)
        printf("\033[31m%d W+X violation(s) found\033[0m.\n", wx_count);
    else
        printf("0 W+X violation(s) found.\n");

    free(vme);
}

void audit_self(void) {
    audit_process_memory(getpid());
}
