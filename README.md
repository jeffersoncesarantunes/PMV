# PMV

Process Mitigation Viewer for OpenBSD — inspects `pledge(2)`, `unveil(2)` and W^X state per process via `libkvm(3)`.

[![CI](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/PMV/ci.yml?style=flat-square&logo=githubactions&label=CI)](https://github.com/jeffersoncesarantunes/PMV/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/PMV/codeql.yml?style=flat-square&logo=codeql&label=CodeQL)](https://github.com/jeffersoncesarantunes/PMV/actions/workflows/codeql.yml)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Tested-On](https://img.shields.io/badge/Tested%20on-OpenBSD%208.0-1793D1?style=flat-square)](https://www.openbsd.org/80.html)

## Why it exists

I wrote PMV because I wanted a quick, straight-to-the-point look at which processes on an OpenBSD system were using `pledge` and `unveil`, without cracking open each binary or running `ktrace` on everything. I wanted something that reads the metadata the kernel exposes through `libkvm` and shows me, in a table, who's mitigated and who isn't. It's not a vulnerability scanner, not a behavioral auditor — it's a state viewer, and that's intentional.

## What it does

Reads `kinfo_proc` via `libkvm(3)` and reports, per process, whether `pledge(2)` was called, whether `unveil(2)` was called, whether it's in `chroot`, and whether there are W^X indicators. It assigns a simple score (0–6) based on which mitigations are present. You can filter by PID, compare current state against an earlier snapshot (`--diff`), and export to JSON or CSV.

PMV protects itself too: it calls `unveil` and `pledge` before listing processes.

## What it doesn't do

- Doesn't reveal *which* `pledge` promises or *which* `unveil` paths — the OpenBSD kernel doesn't expose that to userland.
- Doesn't trace syscalls or do behavioral detection. For that use `ktrace(1)` or `btrace(8)`.
- Doesn't work outside OpenBSD; it depends on `libkvm` and `kinfo_proc`.

## Real-world use cases

Quickly check whether a freshly deployed service is under `pledge` and `unveil` before putting it in production.

Detect mitigation drift: run `--diff` between two snapshots to see if a process gained or lost protections.

Light host audit on OpenBSD: list all processes and spot the ones running with no mitigation at all (score 0).

W^X memory scan by PID (`--scan-wx`) in a lab environment with `kern.allowkmem=1`.

## Example output

```
PID      PPID   PROCESS                PARENT                 PLEDGE  UNVEIL  W^X     SCORE
-----------------------------------------------------------------------------------------------------
89905    57770  pmv                    ksh                    PRESENT PRESENT ok      5
80996    57770  ksh                    xfce4-terminal         PRESENT NONE    ok      3
96837    1      xfce4-terminal         init                   NONE    NONE    ok      0
```

`PRESENT` confirms the mitigation was called — it doesn't say which policy or scope. PIDs, names, and scores vary with your system and privileges.

## Project in Action

![System Scan](./Images/pmv-runtime-scan-v2.png)

![PID Filter](./Images/pmv-pid-filter-v2.png)

![Diff Audit](./Images/pmv-diff-audit-v2.png)

## How to build and use

```bash
git clone https://github.com/jeffersoncesarantunes/PMV.git
cd PMV && make
doas ./pmv
```

PMV needs `libkvm` and elevated privileges to access kernel memory. Run it with `doas` or as root.

| Flag | Purpose |
| :--- | :--- |
| `--pid <PID>` | Inspects a process and its children |
| `--diff` | Compares current state against an earlier snapshot |
| `--scan-wx <PID>` | W^X analysis per memory region |
| `--format json\|csv` | Structured export |
| `--quiet` | Suppresses non-essential output |

## OpenBSD limitations

The kernel exposes just a boolean for `pledge(2)` and `unveil(2)` — presence or absence. Specific promises and paths aren't available to userland. PMV reports what the kernel provides and doesn't pretend otherwise.

`KERN_PROC_VMMAP` is restricted by default on OpenBSD. Deep memory auditing (`--scan-wx`) needs `kern.allowkmem=1` in a lab environment.

## Security

See [SECURITY.md](./SECURITY.md). Don't open public issues for vulnerabilities.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

See [LICENSE](./LICENSE)
