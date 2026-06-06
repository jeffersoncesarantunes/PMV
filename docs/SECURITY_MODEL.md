#  ● Technical Specification: Security Model & Forensic Workflow

This document details the architectural logic of PMV and provides a formal guide on how to interpret and act upon the results using native OpenBSD forensic tools.

---

## 1. Philosophical Foundation

PMV is built on the **"Verify, then Trust"** principle. PMV identifies the "gap" between kernel capability and application adoption.

### 1.1 The "Naked Binary" Problem
A process running without `pledge(2)` or `unveil(2)` is considered a "Naked Binary," providing unrestricted access to system calls and global filesystem scope.

---

## 2. Kernel Telemetry & Visual Representation

### 2.1 Technical Data Source
* **Mechanism:** Direct inspection of `struct kinfo_proc` via `libkvm(3)`.
* **Data Integrity:** Bypasses text-based process lists to avoid TOCTOU vulnerabilities.

### 2.2 UI Chromatic Logic (ANSI Escape Codes)
PMV uses standard ANSI escape sequences to categorize process states:
* **NATIVE (PID ≥ 100):** Blue foreground.
* **KERNEL (PID < 100):** Magenta foreground.
* **Mitigations:** Green (Active) and Red (None).
* **Security Score:** Green (≥ 4), Yellow (1–3), Red (≤ 0).

Actual rendering may vary slightly between terminal emulators; the semantic mapping above is what the code emits.

---

## 3. Post-Audit Investigation Workflow

### Step 1: Behavioral Capture & Dump Analysis
* **Live Trace:** `doas ktrace -p [PID]` (Capture syscalls for 30-60s).
* **Binary Integrity:** `sha256 /path/to/binary` (Check for tampering).
* **Static Analysis:** `strings /path/to/binary | less` (Search for hardcoded IPs/URLs).
* **Hex Inspection:** `hexdump -C /path/to/binary` (Investigate data offsets).

### Step 2: Filesystem & Access Mapping
* **Action:** `doas fstat -p [PID]` and `kdump | grep "NAMI"`.
* **Objective:** Identify unauthorized filesystem probing.

---

## 4. Operational Safety & Resolution

### 4.1 Handling Errors
PMV returns actionable messages for each error case: `EINVAL` from `sysctl(KERN_PROC_VMMAP)` is reported and skipped; memory allocation failures abort cleanly. No interactive prompts are required — the tool either succeeds or reports the specific failure.

### 4.2 Hardening Hierarchy
1. **Code Patching:** Implement `pledge()` and `unveil()` based on gathered data.
2. **Verification:** Rerun PMV to confirm **PRESENT** status.
