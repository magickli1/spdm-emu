# Repository Guidelines

## Project Structure & Module Organization

The top-level `CMakeLists.txt` builds the project’s C99 libraries and sample
applications. Public protocol APIs live in `include/library/`, with matching
implementations under `library/<protocol>_*_lib/`. Emulator programs and shared
runtime code are in `spdm_emu/`: requester and responder entry points have their
own directories, while common transport and storage support is in
`spdm_emu/spdm_emu_common/`. The embedded-oriented example is under
`spdm-device-sample/`. User documentation and images belong in `doc/` and
`doc/assets/`; maintenance helpers belong in `script/`. `libspdm/` and
`SPDM-Responder-Validator/` are submodules—avoid editing them as part of an
unrelated change. Exception: TPM IAK certificate serving intentionally edits
`libspdm/os_stub/spdm_device_secret_lib_tpm/` (for example `read_pub_cert.c`).

## Build, Test, and Development Commands

Initialize dependencies before the first build:

```sh
git submodule update --init --recursive
cmake -S . -B build -DARCH=x64 -DTOOLCHAIN=GCC \
  -DTARGET=Debug -DCRYPTO=openssl
cmake --build build --target copy_sample_key
cmake --build build -j
```

For the TPM/IAK Quote path, configure with `-DDEVICE=tpm` and
`-DLIBSPDM_TPM_SUPPORT=1` (OpenSSL + `tpm2-openssl` / `swtpm` as in
`.github/workflows/build_CI_TPM.yml`). Provision keys with `script/setup-tpm.sh`
before running the emulators; see `doc/tpm.md` and `doc/tpm_quote_design.md`.

Set `-DBUILD_VALIDATOR_SAMPLES=OFF` for a smaller build without the validator
submodule. Built executables are placed in `build/bin/`.

**Normal smoke test:** start `spdm_responder_emu`, then run
`spdm_requester_emu` in a second terminal with default options. See
`doc/spdm_emu.md` for transport and command options.

**TPM Quote smoke test:** configure with `-DDEVICE=tpm` and
`-DLIBSPDM_TPM_SUPPORT=1`, export both `TPM2TOOLS_TCTI` and `TPM2OPENSSL_TCTI`,
run `script/setup-tpm.sh` from `build/bin`, set
`LIBSPDM_TPM_IAK_ROOT_CERT_FILE` on the requester, and use the Quote CLI in
`doc/spdm_emu.md` or `doc/tpm.md`. Expect `TPM Quote verification - PASS` on
the requester.

Run `script/format_nix.sh --check` to verify C/H formatting, or omit `--check`
to apply Uncrustify fixes.

## Coding Style & Naming Conventions

Follow the existing C99 style and `.uncrustify.cfg` (four-column indentation).
Builds enable strict warnings and generally treat them as errors. Use
lowercase `snake_case` for functions, variables, and filenames; use uppercase
`SNAKE_CASE` for macros. Keep public declarations in `include/library/` aligned
with their implementation library. New source files must copy the repository’s
BSD copyright and license header.

## Testing Guidelines

There is no separate top-level unit-test target. At minimum, configure and
compile the affected GCC/OpenSSL build, run the formatter check, and exercise
the requester/responder flow relevant to the change. For validator changes,
leave `BUILD_VALIDATOR_SAMPLES` enabled and build both validator sample targets.
Document exact commands and observed results in the pull request.

## Commit & Pull Request Guidelines

Recent subjects use concise, imperative summaries, sometimes scoped (for
example, `build: fix ...` or `spdm_requester_emu: add ...`). Keep commits
focused. Every commit requires a human DCO sign-off; use `git commit -s`.

Open pull requests against `main`. Explain the motivation and behavior change,
link relevant issues, list build/test evidence, and update documentation when
interfaces or usage change. Include screenshots only when documentation or
visible output benefits from them.
