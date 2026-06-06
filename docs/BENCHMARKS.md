#  ● Performance Benchmarks & Operational Impact

This document provides empirical data regarding the resource consumption and operational safety of PMV on OpenBSD.

---

## 1. Resource Consumption (Average)

PMV is designed to be a lightweight viewer. By interfacing directly with the kernel via `libkvm(3)`, it avoids the overhead of spawning multiple shell processes or heavy parsing.

| Metric | Impact | Notes |
| :--- | :--- | :--- |
| **CPU Usage** | < 0.1% | Negligible during active scans. |
| **RAM (RSS)** | ~1.2 MB | Fixed footprint (no dynamic memory leaks). |
| **I/O Impact** | Negligible (scan) / Minimal (export) | Read-only kernel scan; structured export (`--format json/csv`) writes output.json / output.csv to disk. |

---

## 2. Latency & Scalability

The scanning engine performance scales linearly with the number of active PIDs.

* **Total Scan Time (Standard System - 100 PIDs):** ~0.05 seconds.
* **Total Scan Time (Loaded Server - 500+ PIDs):** ~0.18 seconds.

### 2.1 The "Ptrace-less" Advantage
Unlike debuggers or traditional security scanners, PMV **does not use ptrace(2)**. 
* **Zero Interruption:** Audited processes are never suspended or slowed down.
* **Stability:** There is no risk of crashing a production daemon during the audit.

---

## 3. Safety & Reliability

### 3.1 Kernel State Snapshot
PMV utilizes the `KERN_PROC_ALL` flag. This provides a consistent snapshot of the process table at query time, ensuring stable and reliable reporting even under high process churn.

### 3.2 Error Resilience
PMV handles kernel interface errors gracefully. If `KERN_PROC_VMMAP` sysctl returns `EINVAL` (kernel hardening active), the tool prints an informative message and continues — no crash, no hang. Memory allocation failures are similarly caught and reported.

---
*PMV: Lightweight process mitigation visibility for OpenBSD.*
