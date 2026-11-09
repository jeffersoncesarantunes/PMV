# PMV

Process Mitigation Viewer for OpenBSD — inspeciona `pledge(2)`, `unveil(2)` e estado W^X por processo via `libkvm(3)`.

[![CI](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/PMV/ci.yml?style=flat-square&logo=githubactions&label=CI)](https://github.com/jeffersoncesarantunes/PMV/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/jeffersoncesarantunes/PMV/codeql.yml?style=flat-square&logo=codeql&label=CodeQL)](https://github.com/jeffersoncesarantunes/PMV/actions/workflows/codeql.yml)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Tested-On](https://img.shields.io/badge/Tested%20on-OpenBSD%208.0-1793D1?style=flat-square)](https://www.openbsd.org/80.html)

## Por que existe

Escrevi o PMV porque precisava de uma visão rápida e direta de quais processos em um sistema OpenBSD estavam usando `pledge` e `unveil`, sem ter que abrir cada binário ou rodar `ktrace` para tudo. Queria algo que lesse os metadados expostos pelo kernel via `libkvm` e me mostrasse, em uma tabela, quem está mitigado e quem não está. Não é um scanner de vulnerabilidades, não é um auditor comportamental: é um visualizador de estado, e isso é intencional.

## O que faz

Lê `kinfo_proc` através de `libkvm(3)` e reporta, por processo, se `pledge(2)` foi chamado, se `unveil(2)` foi chamado, se está em `chroot`, e se há indicadores de W^X. Atribui uma pontuação simples (0–6) com base na presença dessas mitigações. Pode filtrar por PID, comparar o estado atual com um snapshot anterior (`--diff`) e exportar em JSON ou CSV.

O próprio PMV se protege: chama `unveil` e `pledge` antes de listar os processos.

## O que não faz

- Não revela *quais* promises do `pledge` ou *quais* caminhos do `unveil` — o kernel do OpenBSD não expõe isso para o userland.
- Não faz rastreamento de syscalls nem detecção comportamental. Para isso use `ktrace(1)` ou `btrace(8)`.
- Não funciona fora do OpenBSD; depende de `libkvm` e `kinfo_proc`.

## Casos de uso reais

Conferir rapidamente se um serviço recém-deployado está sob `pledge` e `unveil` antes de colocá-lo em produção.

Detectar drift de mitigação: rodar `--diff` entre dois snapshots para ver se um processo perdeu ou ganhou proteções.

Auditoria leve de um host OpenBSD: listar todos os processos e identificar os que rodam sem nenhuma mitigação (score 0).

Varredura de memória W^X por PID (`--scan-wx`) em ambiente de laboratório com `kern.allowkmem=1`.

## Saída de exemplo

```
PID      PPID   PROCESS                PARENT                 PLEDGE  UNVEIL  W^X     SCORE
-----------------------------------------------------------------------------------------------------
89905    57770  pmv                    ksh                    PRESENT PRESENT ok      5
80996    57770  ksh                    xfce4-terminal         PRESENT NONE    ok      3
96837    1      xfce4-terminal         init                   NONE    NONE    ok      0
```

`PRESENT` confirma que a mitigação foi chamada — não diz qual política nem escopo. PIDs, nomes e pontuações variam conforme o sistema e os privilégios usados.

## Como construir e usar

```bash
git clone https://github.com/jeffersoncesarantunes/PMV.git
cd PMV && make
doas ./pmv
```

O PMV precisa de `libkvm` e privilégios elevados para acessar a memória do kernel. Rode com `doas` ou como root.

| Flag | Propósito |
| :--- | :--- |
| `--pid <PID>` | Inspeciona um processo e seus filhos |
| `--diff` | Compara o estado atual com um snapshot anterior |
| `--scan-wx <PID>` | Análise W^X por região de memória |
| `--format json\|csv` | Exportação estruturada |
| `--quiet` | Suprime saída não essencial |

## Espelhamento

Este projeto é mantido espelhado no Codeberg, para não depender de uma única plataforma:
https://codeberg.org/jeffersoncesarantunes/PMV

## Limitações do OpenBSD

O kernel expõe apenas um booleano para `pledge(2)` e `unveil(2)` — presença ou ausência. As promises e caminhos específicos não estão disponíveis para o userland. O PMV reporta o que o kernel fornece e não finge o contrário.

`KERN_PROC_VMMAP` é restrito por padrão no OpenBSD. Auditoria profunda de memória (`--scan-wx`) requer `kern.allowkmem=1` em ambiente de laboratório.

## Segurança

Veja [SECURITY.md](./SECURITY.md). Não abra issues públicas para vulnerabilidades.

## Contribuições

Veja [CONTRIBUTING.md](./CONTRIBUTING.md).

## Licença

Veja [LICENSE](./LICENSE)
