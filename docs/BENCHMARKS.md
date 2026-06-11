# Performance Benchmarks & Operational Impact

Real numbers on resource usage and operational safety when running PMV on OpenBSD.

---

## Resource Consumption (Average)

PMV is lightweight. Talking directly to the kernel via `libkvm(3)` means no shell process overhead or heavy parsing.

| Metric | Impact | Notes |
| :--- | :--- | :--- |
| **CPU Usage** | < 0.1% | Negligible during active scans. |
| **RAM (RSS)** | ~1.2 MB | Fixed footprint, no dynamic memory leaks. |
| **I/O Impact** | Negligible (scan) / Minimal (export) | Read-only kernel scan. Structured export with `--format json/csv` writes output files to disk. |

---

## Latency & Scalability

Scan time scales linearly with the number of active PIDs.

* Standard system (~100 PIDs): ~0.05 seconds.
* Loaded server (500+ PIDs): ~0.18 seconds.

### The "Ptrace-less" Advantage

PMV doesn't use ptrace(2). That means:

* Zero interruption — audited processes are never suspended or slowed down.
* No risk of crashing a production daemon mid-audit.

---

## Safety & Reliability

### Kernel State Snapshot

PMV uses `KERN_PROC_ALL` to grab a consistent snapshot of the process table. Stable reporting even when processes are churning hard.

### Error Resilience

Kernel interface errors get handled cleanly. If `KERN_PROC_VMMAP` returns `EINVAL` (kernel hardening is on), PMV prints a message and moves on — no crash, no hang. Same with memory allocation failures.

---

*PMV: Lightweight process mitigation visibility for OpenBSD.*
