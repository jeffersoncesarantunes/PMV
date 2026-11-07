# PMV

Process Mitigation Viewer for OpenBSD — inspects `pledge(2)`, `unveil(2)`, and
W^X state per process via `libkvm(3)`.

[![CI](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/PMV/ci.yml?style=flat-square&logo=githubactions&label=CI)](https://github.com/jeffersoncesarantunes/PMV/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/PMV/codeql.yml?style=flat-square&logo=codeql&label=CodeQL)](https://github.com/jeffersoncesarantunes/PMV/actions/workflows/codeql.yml)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Tested-On](https://img.shields.io/badge/Tested%20on-OpenBSD%208.0-1793D1?style=flat-square)](https://www.openbsd.org/80.html)

## Table of Contents

- [What PMV is](#what-pmv-is)
- [Get started](#get-started)
- [Example output](#example-output)
- [Flags](#flags)
- [Security scoring](#security-scoring)
- [OpenBSD limitations](#openbsd-limitations)
- [When not to use PMV](#when-not-to-use-pmv)
- [Project in Action](#project-in-action)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## What PMV is

PMV reads kernel-exposed process metadata through `libkvm(3)` and `struct
kinfo_proc` to report whether active processes use `pledge(2)`, `unveil(2)`,
and W^X state. It is a viewer, not an auditor, scanner, or vulnerability
finder.

All classification comes from kernel-reported state. PMV does not perform
runtime analysis, syscall tracing, or behavioral detection.

| Does | Does not |
| :--- | :--- |
| Report whether `pledge(2)` was called | Reveal which promises were made |
| Report whether `unveil(2)` was called | Reveal which paths were unveiled |
| Report W^X indicators per process | Trace syscalls or behavior |
| Score processes by mitigation presence | Replace `ktrace(1)` or `btrace(8)` |

## Get started

```bash
git clone https://github.com/jeffersoncesarantunes/PMV.git
cd PMV && make
doas ./pmv
```

PMV needs `libkvm` and elevated privileges to access kernel memory. Run with
`doas` or as root.

## Example output

```text
PID      PPID   PROCESS                PARENT                 PLEDGE  UNVEIL  W^X     SCORE
-----------------------------------------------------------------------------------------------------
89905    57770  pmv                    ksh                    PRESENT PRESENT ok      5
80996    57770  ksh                    xfce4-terminal         PRESENT NONE    ok      3
96837    1      xfce4-terminal         init                   NONE    NONE    ok      0
```

`PRESENT` confirms the mitigation syscall was called — it does not indicate
policy depth or scope. PIDs, process names, and scores vary by system and by
the privileges used to run PMV.

## Flags

| Flag | Purpose |
| :--- | :--- |
| `--pid <PID>` | Inspect one process and its children |
| `--diff` | Compare current state against a previous snapshot |
| `--scan-wx <PID>` | Per-region W^X memory analysis |
| `--format json\|csv` | Structured export |
| `--quiet` | Suppress non-essential output |

## Security scoring

Each process receives a score from **0 to 6**:

| Criteria | Value |
| :------- | :---: |
| `pledge(2)` called | +3 |
| `unveil(2)` called | +2 |
| `chroot` jail | +1 |

| Score | Meaning |
| :---: | :------ |
| 4 – 6 | Multiple mitigations detected |
| 1 – 3 | Partial mitigation |
| 0 | No mitigations detected |

## OpenBSD limitations

The kernel exposes only a boolean for `pledge(2)` and `unveil(2)` — presence or
absence. The specific promises and paths are not available to userland. PMV
reports what the kernel provides and does not pretend otherwise.

`KERN_PROC_VMMAP` is restricted by default on OpenBSD. Deep memory auditing
(`--scan-wx`) requires `kern.allowkmem=1` in a lab environment.

## When not to use PMV

* You need to know *which* `pledge` promises or *which* `unveil` paths a
  process holds — the kernel does not expose them.
* You need syscall tracing or behavioral detection — use `ktrace(1)` or
  `btrace(8)` instead.
* You are not running OpenBSD — PMV depends on `libkvm` and `kinfo_proc`.

## Project in Action

![System Scan](./Images/pmv-runtime-scan-v2.png)

![PID Filter](./Images/pmv-pid-filter-v2.png)

![Diff Audit](./Images/pmv-diff-audit-v2.png)

## Security

See [SECURITY.md](./SECURITY.md). Do not open public issues for security
vulnerabilities.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

See [LICENSE](./LICENSE)
