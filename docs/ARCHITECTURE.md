PMV(8) - Process Mitigation Viewer - Architecture
=================================================

PMV is a read-only viewer for OpenBSD process-level mitigation state.
It reads kernel process table entries via kvm(3) and reports whether
pledge(2), unveil(2), and W^X enforcement are active per process.


DESIGN PRINCIPLES
-----------------

1. Read-only. No process interaction, no ptrace(2), no kernel state
   modification.

2. Kernel-exposed only. PMV reports what the kernel puts in
   struct kinfo_proc. No inference, no speculation, no simulation.

3. Self-hardened. PMV calls pledge(2) and unveil(2) on itself before
   processing anything. A security tool should practice what it
   preaches.


DATA FLOW
---------

kvm_openfiles(3)
  -> kvm_getprocs(3) with KERN_PROC_ALL
    -> struct kinfo_proc array
      -> PS_PLEDGE, PS_UNVEIL, PS_WXNEEDED, P_CHROOT flags
        -> scoring
          -> pledge(2) + unveil(2) lockdown
            -> output (terminal, JSON, or CSV)

Step 1 - kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, errbuf)

  Opens the live kernel memory image. KVM_NO_FILES tells kvm(3) that
  no crash dump or system file is needed -- PMV reads the running
  kernel directly. Returns NULL on failure, usually because of
  insufficient privileges or /dev/kmem being inaccessible.

Step 2 - kvm_getprocs(kd, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc),
                      &nprocs)

  Returns the full process table as an array of struct kinfo_proc.
  KERN_PROC_ALL grabs every process and kernel thread. The kernel
  allocates and fills the array; PMV only reads it. A NULL return
  means kvm_getprocs(3) failed, which is unusual on a running system.

Step 3 - Flag inspection (engine.c:50-57)

  Each kinfo_proc entry has two flag fields PMV cares about:

    p_psflags bitmask:
      PS_PLEDGE    (0x00000004) - pledge(2) has been called
      PS_UNVEIL    (0x01000000) - unveil(2) has been called
      PS_WXNEEDED  (0x00040000) - process needs W^X exception

    p_flag bitmask:
      P_CHROOT     (0x00004000) - process is chrooted

  All four are booleans. Single-bit flags in the process structure.
  No depth, no scope, no policy detail. This is a kernel ABI
  constraint, not a missing feature.

Step 4 - PPID resolution (engine.c:60-70)

  A second pass maps each process to its parent name by matching ppid
  against pid entries in the same array. Processes whose parent isn't
  found (kernel threads, orphaned processes) show up as
  "(kernel/init)".

Step 5 - Scoring (engine.c:80-89)

  score = (pledge ? +3 : 0) + (unveil ? +2 : 0) + (chroot ? +1 : 0)
          + (wxneeded ? -2 : 0)

  Range: -2 to 6.

  The weights aren't scientific -- they reflect the relative impact
  of each mitigation:

    +3  pledge(2) restricts the syscall surface. Broadest, most
        impactful mitigation on OpenBSD.

    +2  unveil(2) restricts filesystem access. Narrower, but still
        valuable.

    +1  chroot adds filesystem containment on top of unveil.

    -2  wxneeded means the binary asked for a W^X exception, which
        implies writable+executable memory pages exist.

  The score is a quick visual signal. A low score doesn't mean a
  process is compromised -- plenty of OpenBSD base system daemons
  don't use pledge(2) or unveil(2).

Step 6 - Self-hardening (main.c:315-316)

  After collecting process data but before producing output, PMV
  locks itself down:

    unveil(".", "rwc")            -- current dir for all file I/O
    unveil("/dev", "r")           -- libkvm reads /dev/kmem
    unveil(NULL, NULL)            -- block all further filesystem access

    pledge("stdio rpath wpath cpath ps vminfo unveil", NULL)

    stdio   -- standard I/O (terminal output)
    rpath   -- read-access to files (libkvm, snapshot loading)
    wpath   -- write-access to files (export, snapshot)
    cpath   -- create files
    ps      -- kvm_getprocs(3) access
    vminfo  -- sysctl KERN_PROC_VMMAP access (used by --scan-wx)
    unveil  -- allow the unveil syscall (already used above)

  The unveil(2) calls come before pledge(2) because pledge(2)
  restrictions take effect immediately, while unveil(2) needs all
  path entries set before the NULL terminator.

  If either pledge(2) or unveil(2) fails, PMV calls err(3) and
  exits. It won't run unhardened.


OUTPUT FORMATS
--------------

Terminal (default)

  Color-coded table with per-process mitigation columns:
  PID, PPID, PROCESS, PARENT, PLEDGE, UNVEIL, W^X, SCORE.
  Blue rows for native processes, magenta for kernel threads
  (PID < 100). Paged every 20 lines via getchar(). Summary
  block at the end: total processes, pledge count, unveil count,
  W^X violations.

JSON (--format json)

  Structured array of objects. Each object contains pid, ppid,
  name, ppname, pledge (bool), unveil (bool), wxneeded (bool),
  chrooted (bool), context ("NATIVE" or "KERNEL"), score.
  In quiet mode (--quiet), writes to output.json.

CSV (--format csv)

  Header row plus one line per process. Same fields as JSON.
  In quiet mode, writes to output.csv.


DIFF MODE (--diff)
------------------

PMV saves a snapshot file (.pmv_snapshot) on every normal run
(anything that isn't --diff). The format is pipe-delimited:

    PID|NAME|HAS_PLEDGE|HAS_UNVEIL|WXNEEDED

When --diff is passed, PMV loads the previous snapshot before
running the current scan, then compares and displays:

  ~  process whose mitigation state changed
  +  new process since the last snapshot
  -  process that exited

The snapshot doesn't update when --diff is used. This lets you
run repeated comparisons against the same baseline.

The snapshot is plain text and unauthenticated. Not suitable as
a chain-of-custody mechanism without external integrity verification
(e.g., sha256(1)).


W^X MEMORY SCAN (--scan-wx <PID>)
----------------------------------

Uses sysctl(2) with KERN_PROC_VMMAP to enumerate all memory
regions for a single process. Reports:

  - Start and end address of each mapped region (hex)
  - Protection flags (rwx triple)
  - W+X violations highlighted in red

KERN_PROC_VMMAP is restricted by default on OpenBSD to prevent
ASLR bypass from userspace. On a stock install, PMV prints:

  [!] VMMAP sysctl failed for PID X: KERN_PROC_VMMAP is restricted

To enable deep memory scanning, flip the kernel knob:

  doas sysctl kern.allowkmem=1

Only do this in a lab environment. Production systems should leave
kern.allowkmem at its default (0).


LIMITATIONS
-----------

1. Pledge/unveil are booleans. The OpenBSD kernel exposes whether
   pledge(2) and unveil(2) were called, but not which promises were
   pledged or which paths were unveiled. PMV can't report what the
   kernel doesn't provide. Any tool claiming to show pledge promise
   depth or unveil path scope is either guessing or using
   ktrace(1)-style runtime tracing, not kernel-exposed state.

2. No runtime analysis. PMV reads a point-in-time snapshot from
   kvm(3). It doesn't trace syscalls, profile runtime behavior, or
   detect policy violations during execution. For syscall tracing,
   use ktrace(1) or btrace(8).

3. PS_WXNEEDED vs. actual W^X pages. PS_WXNEEDED in kinfo_proc
   means the binary requested a W^X exception via mimmutable(2) or
   similar. It is NOT a per-region memory map. The separate --scan-wx
   flag uses KERN_PROC_VMMAP for actual per-region analysis, but
   needs kern.allowkmem=1.

4. Snapshot integrity. The .pmv_snapshot file is plain text with no
   cryptographic signature. If tampered with, --diff will produce
   misleading results. Fine for ad-hoc investigations, but not for
   forensic chain-of-custody.

5. Performance under load. kvm_getprocs(3) returns a point-in-time
   snapshot. Under extreme process churn, PIDs can appear or
   disappear between the kvm_getprocs(3) call and the PPID
   resolution pass. That's an inherent race in anything that reads
   /proc or kvm(3). PMV handles it gracefully (unknown parent ->
   "(kernel/init)"), but the process table isn't a static artifact.


PORTABILITY
-----------

OpenBSD only. PMV depends on:

  kvm(3)                     -- OpenBSD-specific kernel memory interface
  struct kinfo_proc          -- OpenBSD kernel ABI
  PS_PLEDGE, PS_UNVEIL       -- OpenBSD-specific process flags
  PS_WXNEEDED, P_CHROOT      -- OpenBSD-specific process flags
  KERN_PROC_VMMAP sysctl     -- OpenBSD-specific sysctl MIB

Won't work on Linux, FreeBSD, NetBSD, or any other system. That's
intentional -- every BSD exposes process mitigation state differently,
and PMV targets the OpenBSD security model specifically.


SEE ALSO
--------

pledge(2), unveil(2), kvm(3), kvm_getprocs(3), kinfo_proc(3),
sysctl(2), ktrace(1), btrace(8), sha256(1)
