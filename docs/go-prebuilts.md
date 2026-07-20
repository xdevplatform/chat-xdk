# Go prebuilt static libraries

The Go binding links against committed static libraries under
`go/chatxdk/libs/<os>_<arch>/` so consumers need no Rust toolchain. This document
covers how those prebuilts are produced and kept in sync. It is for contributors
modifying the Rust core, not for consumers of the Go module.

## Rebuilding locally

```bash
make prebuilt   # build + copy the .a for your current platform, then commit it
make test-go    # runs prebuilt first, then go test
```

Requires Rust (stable, via [rustup](https://rustup.rs/)). To update a platform you
don't have locally, run `make prebuilt` on that machine (or a Linux Docker
container) and commit the resulting `.a`.

## CI

`go-prebuilts.yml` (manual run) and `go-bindings-release.yml` (tag
`go/chatxdk/v*` — the subdir-module tag pushed by the release workflow — or a
manual `go/v*` tag, for a GitHub Release tarball) can build prebuilts.

### Linux (glibc + musl)

Committed archives:

- `go/chatxdk/libs/linux_amd64/libchat_xdk_go.a` (glibc)
- `go/chatxdk/libs/linux_amd64_musl/libchat_xdk_go.a` (musl / Alpine)

`go-prebuilt-linux.yml`:

1. **Pull requests** — rebuilds both targets on Ubuntu and fails if either file
   does not match (including fork PRs, where a bot cannot push a fix for you).
2. **Pushes / workflow_dispatch** — rebuilds both and, if the bytes differ,
   commits and pushes the new files to the same branch. Pushes that only touch
   `go-prebuilt-linux.yml` still count (that path is in `on.push.paths`); a
   follow-up commit only under `libs/**` re-triggers, and the sync step is a
   no-op when the files already match, so it does not loop.

`ci.yml` does not contain a separate verify job for this; it lives in
`go-prebuilt-linux.yml`.

**Branch protection:** if the default `GITHUB_TOKEN` cannot push, add a repository
secret `PREBUILT_SYNC_PAT` (PAT with `contents: write` for this repo).

**Manual run:** GitHub → Actions → go prebuilt (linux) → Run workflow → set ref
to your branch (default `main`).

The musl variant is selected at build time via the `musl` Go build tag
(`go build -tags musl`), which links against `libs/linux_amd64_musl/` instead of
`libs/linux_amd64/`.

### Darwin (arm64 + amd64)

Committed archives:

- `go/chatxdk/libs/darwin_arm64/libchat_xdk_go.a`
- `go/chatxdk/libs/darwin_amd64/libchat_xdk_go.a`

`go-prebuilt-darwin.yml` mirrors Linux: PR verify (rebuild both Apple targets on
`macos-latest`, `strip -S`, byte-compare) and push / workflow_dispatch sync (one
commit updating either or both `.a` files). Uses `MACOSX_DEPLOYMENT_TARGET=11.0`
to align with the `Makefile` / local `make prebuilt`.

**Bootstrap:** if `darwin_amd64/` is not yet in the tree, run Actions → go
prebuilt (darwin) → Run workflow on your branch once so sync adds both archives.

#### Reproducibility (darwin)

The darwin build is made byte-reproducible so a fresh build matches the
committed archive:

- `RUSTFLAGS=-C codegen-units=1` — parallel codegen makes the macOS object code
  vary run-to-run; a single codegen unit is deterministic. (Linux is already
  reproducible with the default profile; its strip step passes `-D` to pin GNU
  deterministic-archive mode explicitly.)
- `ZERO_AR_DATE=1` is exported for the build and strip steps so cctools
  `ar`/`ranlib`/`libtool`/`strip` write zeroed member dates instead of the
  build time.
- After `strip -S`, `scripts/normalize_ar_dates.py` zeroes the 12-byte date
  field of **every** ar member header, guaranteeing byte-identical archives
  regardless of which tool wrote a header. Both the verify and sync jobs and
  `make prebuilt` run the same script, so local builds match CI byte-for-byte.
