# Contributing to PMV

Thank you for considering a contribution to PMV! This is an OpenBSD-specific
process mitigation visibility tool. Please read this guide before submitting
pull requests or opening issues.

## How to contribute

1. **Fork the repository** on GitHub or Codeberg.
2. **Create a feature branch** from `main`: `git checkout -b feature/your-feature`
3. **Make your changes** following the code style (see `.clang-format`).
4. **Run the test suite**: `make test` (portable unit tests) and, on OpenBSD,
   `make verify` (integration tests in the OpenBSD VM).
5. **Commit with a conventional message** (see Commit Style below).
6. **Open a pull request** against `main`. Link any related issue.

## Code style

- C11, follow `.clang-format` (run `clang-format -i src/*.c include/*.h`).
- Compiler warnings must be clean: `-Wall -Wextra -O2`.
- Use `pledge(2)` / `unveil(2)` self-hardening where applicable.
- Document new flags and behavior in `README.md`.

## Commit style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add --diff snapshot comparison
fix: correct JSON escaping of control bytes
docs: document W^X scoring table in README
test: add snapshot codec roundtrip test
ci: add OpenBSD 8.0 VM job
```

Types: `feat`, `fix`, `docs`, `test`, `ci`, `chore`, `refactor`, `security`.

## Reporting security vulnerabilities

Please do **not** open public issues for security vulnerabilities. Instead, see
`SECURITY.md` for our disclosure policy and contact information.

## License

By contributing, you agree that your contributions will be licensed under the
MIT License (see `LICENSE`).
