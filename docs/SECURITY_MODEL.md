# Security Model & Forensic Workflow

How PMV works from a security standpoint and how to investigate the results using standard OpenBSD tools.

---

## Philosophical Foundation

PMV follows a "Verify, then Trust" approach. It highlights the gap between what the kernel can do and what applications actually use.

### The "Naked Binary" Problem

A process running without `pledge(2)` or `unveil(2)` is a "naked binary" — unrestricted access to system calls and the whole filesystem.

---

## Kernel Telemetry & Visual Representation

### Technical Data Source

The data comes from directly inspecting `struct kinfo_proc` via `libkvm(3)`. This bypasses text-based process lists, eliminating the TOCTOU window between reading and displaying.

### UI Chromatic Logic (ANSI Escape Codes)

PMV uses ANSI escape sequences to color-code process states:

* **NATIVE (PID >= 100):** Blue foreground.
* **KERNEL (PID < 100):** Magenta foreground.
* **Mitigations:** Green (active), Red (none).
* **Security Score:** Green (>= 4), Yellow (1-3), Red (<= 0).

The exact rendering depends on your terminal, but the mappings above are what the code emits.

---

## Post-Audit Investigation Workflow

### Step 1: Behavioral Capture & Dump Analysis

* **Live Trace:** `doas ktrace -p [PID]` — capture syscalls for 30-60 seconds.
* **Binary Integrity:** `sha256 /path/to/binary` — check for tampering.
* **Static Analysis:** `strings /path/to/binary | less` — look for hardcoded IPs or URLs.
* **Hex Inspection:** `hexdump -C /path/to/binary` — dig into data offsets.

### Step 2: Filesystem & Access Mapping

Run `doas fstat -p [PID]` and `kdump | grep "NAMI"` to spot unauthorized filesystem probing.

---

## Operational Safety & Resolution

### Handling Errors

Error handling is straightforward: `EINVAL` from `sysctl(KERN_PROC_VMMAP)` gets reported and skipped. Memory allocation failures trigger a clean abort. No interactive prompts — the tool either succeeds or tells you what failed.

### Hardening Hierarchy

1. Patch the code to add `pledge()` and `unveil()` based on what you found.
2. Rerun PMV to confirm the status changed to **PRESENT**.
