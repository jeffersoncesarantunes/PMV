PMV - Security Model
====================

This document describes the kernel interfaces PMV uses, the error
conditions it handles, and how to investigate processes identified
as having weak or missing mitigations.


Kernel Interface
----------------

PMV reads mitigation state exclusively from struct kinfo_proc via
kvm_getprocs(3).  The relevant flags:

  Flag                    Field           Meaning
  PS_PLEDGE   (0x00000004) p_psflags     pledge(2) was called
  PS_UNVEIL   (0x01000000) p_psflags     unveil(2) was called
  PS_WXNEEDED (0x00040000) p_psflags     W^X exception requested
  P_CHROOT    (0x00004000) p_flag        Process is chrooted

These are single-bit boolean flags.  The kernel does not expose
pledge promise lists, unveil path lists, or any other policy detail
to userspace.  This is a kernel ABI constraint, not a missing feature.


W^X Memory Scan (--scan-wx)
----------------------------

For per-process memory region analysis, PMV calls sysctl(2) with
KERN_PROC_VMMAP.  Possible failures:

  EINVAL    KERN_PROC_VMMAP is restricted.
            Action: doas sysctl kern.allowkmem=1.
            This is the default state on OpenBSD.  Only enable
            in lab environments.

  EACCES    Process not owned by caller.
  EPERM     Insufficient privileges.

  Other     Unusual kernel interface error.  Re-run.  If persistent,
            check kernel logs.

Only one PID per invocation.  Output lists every mapped region with
protection flags (rwx) and highlights W+X violations in red.


Error Handling
--------------

kvm_openfiles(3) fails:
  Cause: /dev/kmem inaccessible or insufficient privileges.
  Action: Run with doas.  Verify /dev/kmem exists and is readable
          by the kmem group.

kvm_getprocs(3) fails:
  Cause: Kernel memory corruption or kvm(3) internal state error.
  Action: Rare.  Re-run.  If persistent, suspect kernel issues.

pledge(2) or unveil(2) self-hardening fails:
  Cause: OpenBSD version too old or system call unavailable.
  Action: PMV calls err(3) and exits.  OpenBSD 6.4+ required.

sysctl KERN_PROC_VMMAP returns EINVAL:
  Cause: kern.allowkmem=0 (stock OpenBSD default).
  Action: Accept that --scan-wx is unavailable, or set
          kern.allowkmem=1 temporarily for analysis.
          Not recommended on production systems.

malloc(3) or reallocarray(3) fails:
  Cause: Out of memory.
  Action: PMV returns NULL for process list, triggering an error
          message.  Unusual on a system with available RAM.


Post-Audit Investigation
------------------------

Processes reported as NONE for pledge and unveil have no mitigation
active.  To investigate further:

1. Behavioral capture:
     doas ktrace -p <PID>       Capture syscalls (30-60s)
     doas sha256 /path/to/binary
     strings /path/to/binary | less

2. Filesystem mapping:
     doas fstat -p <PID>
     kdump | grep "NAMI"         Show accessed file paths

3. Remediation:
     Patch the binary to call pledge(2) and unveil(2) at startup,
     then re-run PMV to confirm PRESENT status.

See ktrace(1), fstat(1), kdump(1), sha256(1), pledge(2), unveil(2).
