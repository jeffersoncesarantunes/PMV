PMV - Process Mitigation Viewer
================================

Platform: OpenBSD (tested on 7.9)
Language: C11
License: MIT


Description
-----------

PMV is a read-only viewer for OpenBSD process-level mitigation state.
It reads kernel process table entries via kvm(3) and reports whether
pledge(2), unveil(2), and W^X enforcement are active per process.

All reporting is based strictly on kernel-exposed struct kinfo_proc
flags.  PMV does not perform runtime analysis, syscall tracing, or
behavioral detection.  It reports what the kernel exposes -- nothing
more, nothing less.

The tool hardens itself at runtime by calling pledge(2) and unveil(2)
before processing any data, and runs a W^X self-check on startup.


Options
-------

-h, --help         Display usage and exit
-q, --quiet        Suppress terminal output (useful with --format)
--pid <PID>        Show only the specified PID and its children
--format <fmt>     Export format: json or csv
--diff             Compare current state against last saved snapshot
--scan-wx <PID>    Enumerate memory regions for a single PID


Exit Status
-----------

The program exits 0 on success, 1 on error (kvm failure, pledge/unveil
failure, invalid arguments).


Example Output
--------------

PID      PPID   PROCESS              PARENT               PLEDGE  UNVEIL  W^X     SCORE
-----------------------------------------------------------------------------------------------------
89905    57770  pmv                  ksh                  PRESENT PRESENT ok      5
80996    57770  ksh                  xfce4-terminal       PRESENT NONE    ok      3
96837    1      xfce4-terminal       init                 NONE    NONE    ok      0
18100    <PID>  firefox              firefox              NONE    NONE    ok      0
79750    1      accounts-daemon      init                 NONE    NONE    ok      0

PRESENT means the syscall was called.  The kernel does not expose
which pledges were made or which paths were unveiled.  W^X shows
the process's PS_WXNEEDED flag, not a per-region memory map.

Blue rows are native processes (PID >= 100).  Magenta rows are
kernel threads (PID < 100).


Scoring
-------

Each process receives a score from -2 to 6:

  +3  pledge(2) called
  +2  unveil(2) called
  +1  chroot jail
  -2  W^X exception flag (wxneeded)

  4-6   green -- multiple mitigations detected
  1-3   yellow -- partial mitigation
  <=0   red -- no mitigations detected

The weights are approximate.  A low score does not mean a process is
compromised -- many OpenBSD base system daemons do not use pledge(2)
or unveil(2).


Build and Run
-------------

  git clone https://github.com/jeffersoncesarantunes/PMV.git
  cd PMV
  make clean && make

  doas ./pmv
  doas ./pmv --pid <PID>
  doas ./pmv --format json --quiet
  doas ./pmv --diff
  doas ./pmv --scan-wx <PID>

Generated artifacts:
  output.json       JSON export (when --format json --quiet)
  output.csv        CSV export  (when --format csv --quiet)
  .pmv_snapshot     Diff snapshot (auto-generated on normal runs)


Requirements
------------

- OpenBSD (release or -current)
- libkvm
- BSD make
- doas or root privileges

PMV requires access to kernel memory via kvm(3), which demands
elevated privileges.  The recommended execution method is doas.
The build system installs without setuid root (mode 755), following
OpenBSD's principle of explicit privilege elevation.


Caveats
-------

- Pledge and unveil status are booleans.  The kernel exposes whether
  the syscall was called, but not which promises or paths were used.
  PMV cannot report what the kernel does not provide.

- PS_WXNEEDED indicates the binary requested a W^X exception via
  mimmutable(2), not that a W+X memory region currently exists.
  For per-region analysis, use --scan-wx.  This requires
  kern.allowkmem=1 on default OpenBSD installations.

- The .pmv_snapshot file is plain text, pipe-delimited, and
  unauthenticated.  It is not suitable for evidence chain-of-custody
  without external integrity verification (sha256(1)).


Files
-----

docs/ARCHITECTURE.md   Data flow, self-hardening, portability
docs/BENCHMARKS.md     Performance and resource consumption
docs/SECURITY_MODEL.md Kernel interface, error handling, forensics


See Also
--------

pledge(2), unveil(2), kvm(3), kvm_getprocs(3), kinfo_proc(3),
sysctl(2), ktrace(1), btrace(8), sha256(1), doas(1)
