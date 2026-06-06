PMV - Performance Benchmarks
============================

Measured on OpenBSD 7.9 (AMD64, 8 cores, 16 GB RAM, NVMe SSD).
Numbers will vary by hardware and kernel version.


Resource Usage
--------------

  CPU:    < 0.1% during active scan
  RAM:    ~1.2 MB RSS (fixed, no dynamic growth)
  I/O:    Negligible (read-only kvm call; export writes
          output.json/.csv only when --format is used)


Latency
-------

  100 PIDs:     ~0.05s  (typical desktop or laptop)
  500+ PIDs:    ~0.18s  (loaded server)

Scales linearly with process count.  JSON/CSV export adds < 0.01s.
The --scan-wx pass adds ~0.01s for most processes, up to ~0.1s for
processes with many mapped regions (browsers, JIT runtimes).


Worst-Case Notes
----------------

- Systems with 2000+ PIDs may approach 1s due to the O(n) kvm scan
  and O(n-squared) PPID resolution pass.

- The PPID name lookup walks the process list once per entry
  (engine.c:60-70).  For n < 500 this is negligible.  For n > 2000
  it may account for 100-200ms.

- PMV allocates calloc(nprocs, sizeof(ProcessInfo)) once.  No swap
  or disk thrashing occurs during normal operation.


Why No ptrace(2)
----------------

PMV reads a kvm(3) snapshot and does not attach to any process:

  (-) No per-process syscall details (use ktrace(1))
  (+) Zero interruption of running processes
  (+) No risk of crashing a production daemon
  (+) Consistent snapshot even under process churn


Caveats
-------

- These numbers are from one hardware configuration.  Actual
  performance depends on kernel version, CPU clock, and memory
  bandwidth.

- The diff mode snapshot load and save operations add ~0.01s per
  run on NVMe/SSD storage.  Spinning disks will be slower.

- kvm_getprocs(3) returns a point-in-time snapshot.  Under extreme
  process churn, the PID list may change between the kvm call and
  the PPID resolution pass.  This is a inherent race in any tool
  reading /proc or kvm(3).  PMV handles it gracefully by displaying
  "(kernel/init)" for orphaned entries.
