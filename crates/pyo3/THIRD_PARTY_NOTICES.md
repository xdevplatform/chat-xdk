# Third-Party Notices

This product (`chat-xdk`) includes or links third-party software. This file lists
those components and their licenses so redistributors can meet attribution and
notice requirements.

**Project license:** MIT — see [`LICENSE`](LICENSE) (Copyright (c) 2026 X Corp.).

**Generated from:** `Cargo.lock` / `cargo tree -p chat-xdk-core` as of 2026-07-20.
Re-run a dependency inventory (or regenerate this file) when the lockfile changes
materially, especially around crypto, Thrift, or Juicebox.

## License elections

Where a dependency is dual- or multi-licensed, this project uses it as follows
unless a more specific note below says otherwise:

| Upstream expression | Election used by chat-xdk |
|---------------------|---------------------------|
| MIT OR Apache-2.0 (either order, including `MIT/Apache-2.0`) | **MIT** |
| BSD-2-Clause OR Apache-2.0 OR MIT | **MIT** |
| Unlicense OR MIT | **MIT** |
| Apache-2.0 OR ISC OR MIT | **MIT** |
| Apache-2.0 OR BSL-1.0 | **Apache-2.0** |
| JNA (LGPL-2.1-or-later OR Apache-2.0) | **Apache-2.0** (JVM binding only) |

This file is provided for attribution. It does not modify the licenses of the
third-party components.

---

## Special notices (read these)

These components have notice or copyright terms beyond a plain MIT SPDX tag.

### Apache Thrift (`thrift`) — Apache-2.0

Always linked into the core library (wire protocol).

```
Apache Thrift
Copyright (C) 2006 - 2019, The Apache Software Foundation

This product includes software developed at
The Apache Software Foundation (http://www.apache.org/).
```

Full license text: https://www.apache.org/licenses/LICENSE-2.0

### `subtle` — BSD-3-Clause

Always linked into the core library (constant-time crypto helpers).

```
Copyright (c) 2016-2017 Isis Agora Lovecruft, Henry de Valence. All rights reserved.
Copyright (c) 2016-2024 Isis Agora Lovecruft. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### Juicebox SDK — MIT

Optional feature `juicebox` (default for native builds). Copyright and MIT terms
from upstream:

```
Copyright 2023 Juicebox Systems, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Source: https://github.com/juicebox-systems/juicebox-sdk

### `ring` — Apache-2.0 AND ISC (Juicebox / TLS path only)

Pulled in via Juicebox networking (`reqwest` → `rustls` → `ring`). Upstream ships
multiple license texts (`LICENSE`, `LICENSE-BoringSSL`, `LICENSE-other-bits`).
When redistributing a binary built **with** the Juicebox feature, include those
upstream license texts (available from the `ring` crate sources on crates.io /
https://github.com/briansmith/ring).

### `webpki-roots` — MPL-2.0 (Juicebox / TLS path only)

Mozilla CA root bundle used by `reqwest` when Juicebox is enabled.

This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.

### Unicode data — Unicode License v3 (Juicebox / URL stack; also `unicode-ident`)

ICU4X crates (`icu_*`, etc.) used for IDNA/URL processing under the Juicebox
feature, and `unicode-ident` (build/proc-macro path), include Unicode data
under the Unicode License v3:

```
UNICODE LICENSE V3

COPYRIGHT AND PERMISSION NOTICE

Copyright © 1991-2023 Unicode, Inc.

NOTICE TO USER: Carefully read the following legal agreement. BY
DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR
SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE
TERMS AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT
DOWNLOAD, INSTALL, COPY, DISTRIBUTE OR USE THE DATA FILES OR SOFTWARE.

Permission is hereby granted, free of charge, to any person obtaining a
copy of data files and any associated documentation (the "Data Files") or
software and any associated documentation (the "Software") to deal in the
Data Files or Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, and/or sell
copies of the Data Files or Software, and to permit persons to whom the
Data Files or Software are furnished to do so, provided that either (a)
this copyright and permission notice appear with all copies of the Data
Files or Software, or (b) this copyright and permission notice appear in
associated Documentation.

THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
THIRD PARTY RIGHTS.

IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA
FILES OR SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall
not be used in advertising or otherwise to promote the sale, use or other
dealings in these Data Files or Software without prior written
authorization of the copyright holder.
```

### `encoding_rs` — (Apache-2.0 OR MIT) AND BSD-3-Clause (Juicebox path)

Encoding detection/conversion via `reqwest`. Dual-licensed Apache-2.0/MIT for
code; includes WHATWG encoding data under BSD-3-Clause. Copyright Mozilla
Foundation. See the `encoding_rs` crate for full `LICENSE-*` / `COPYRIGHT` files.

---

## JVM binding dependencies

These are direct dependencies of the published Java artifact (`com.x:chatxdk`),
in addition to the native Rust library.

| Component | Version | License | Notes |
|-----------|---------|---------|--------|
| Java Native Access (JNA) | 5.14.0 | LGPL-2.1-or-later **OR** Apache-2.0 | **Used under Apache-2.0** |
| jackson-databind | 2.17.2 | Apache-2.0 | Transitive Jackson modules same family |

JNA: https://github.com/java-native-access/jna  
Jackson: https://github.com/FasterXML/jackson-databind

---

## Rust runtime inventory

Lists below are **runtime** dependencies of `chat-xdk-core` (`cargo tree --edges normal`).
Build-only tools (e.g. `csbindgen`) and test-only crates are omitted.

Versions are from the repository `Cargo.lock` at generation time.

## Core library (always — Juicebox feature disabled)

### Apache-2.0

- `thrift@0.24.0`

### BSD-3-Clause

- `subtle@2.6.1`

### (MIT OR Apache-2.0) AND Unicode-3.0

- `unicode-ident@1.0.24`

### MIT

- `generic-array@0.14.7`
- `integer-encoding@3.0.4`
- `ordered-float@3.9.2`
- `zmij@1.0.21`

### MIT OR Apache-2.0 (used under MIT)

- `aead@0.5.2`
- `aes-gcm@0.10.3`
- `aes@0.8.4`
- `base16ct@0.2.0`
- `base64@0.22.1`
- `base64ct@1.8.3`
- `block-buffer@0.10.4`
- `block-padding@0.3.3`
- `cfg-if@1.0.4`
- `chacha20@0.9.1`
- `cipher@0.4.4`
- `const-oid@0.9.6`
- `cpufeatures@0.2.17`
- `crypto-bigint@0.5.5`
- `crypto-common@0.1.7`
- `crypto_secretstream@0.2.0`
- `ctr@0.9.2`
- `der@0.7.10`
- `digest@0.10.7`
- `ecdsa@0.16.9`
- `elliptic-curve@0.13.8`
- `ff@0.13.1`
- `getrandom@0.2.17`
- `ghash@0.5.1`
- `group@0.13.0`
- `hex@0.4.3`
- `hkdf@0.12.4`
- `hmac@0.12.1`
- `inout@0.1.4`
- `itoa@1.0.17`
- `libc@0.2.183`
- `log@0.4.29`
- `num-traits@0.2.19`
- `num_cpus@1.17.0`
- `opaque-debug@0.3.1`
- `p256@0.13.2`
- `pem-rfc7468@0.7.0`
- `pkcs8@0.10.2`
- `poly1305@0.8.0`
- `polyval@0.6.2`
- `ppv-lite86@0.2.21`
- `primeorder@0.13.6`
- `proc-macro2@1.0.106`
- `quote@1.0.45`
- `rand@0.8.5`
- `rand_chacha@0.3.1`
- `rand_core@0.6.4`
- `rfc6979@0.4.0`
- `salsa20@0.10.2`
- `sec1@0.7.3`
- `serde@1.0.228`
- `serde_core@1.0.228`
- `serde_derive@1.0.228`
- `serde_json@1.0.149`
- `sha2@0.10.9`
- `signature@2.2.0`
- `spki@0.7.3`
- `syn@2.0.117`
- `thiserror-impl@1.0.69`
- `thiserror@1.0.69`
- `threadpool@1.8.1`
- `typenum@1.19.0`
- `universal-hash@0.5.1`
- `uuid@1.22.0`
- `xsalsa20poly1305@0.9.1`
- `zeroize@1.8.2`
- `zeroize_derive@1.4.3`

### BSD-2-Clause OR Apache-2.0 OR MIT (used under MIT)

- `zerocopy@0.8.42`

### Unlicense OR MIT (used under MIT)

- `byteorder@1.5.0`
- `memchr@2.8.0`


## Additional components with Juicebox feature enabled (default on native)

### Apache-2.0

- `ciborium-io@0.2.2`
- `ciborium-ll@0.2.2`
- `ciborium@0.2.1`
- `sync_wrapper@0.1.2`

### BSD-3-Clause

- `curve25519-dalek@4.1.3`
- `ed25519-dalek@2.2.0`
- `instant@0.1.12`
- `x25519-dalek@2.0.1`

### BSD-2-Clause

- `coarsetime@0.1.37`

### ISC

- `hmac-sha1-compact@1.1.7`
- `hmac-sha256@1.1.14`
- `hmac-sha512@1.1.12`
- `jwt-simple@0.11.7`
- `rustls-webpki@0.101.7`
- `untrusted@0.9.0`

### MPL-2.0

- `webpki-roots@0.25.4`

### Apache-2.0 AND ISC

- `ring@0.17.14`

### Unicode-3.0

- `icu_collections@2.1.1`
- `icu_locale_core@2.1.1`
- `icu_normalizer@2.1.1`
- `icu_normalizer_data@2.1.1`
- `icu_properties@2.1.2`
- `icu_properties_data@2.1.2`
- `icu_provider@2.1.1`
- `litemap@0.8.1`
- `potential_utf@0.1.4`
- `tinystr@0.8.2`
- `writeable@0.6.2`
- `yoke-derive@0.8.1`
- `yoke@0.8.1`
- `zerofrom-derive@0.1.6`
- `zerofrom@0.1.6`
- `zerotrie@0.2.3`
- `zerovec-derive@0.11.2`
- `zerovec@0.11.5`

### (Apache-2.0 OR MIT) AND BSD-3-Clause

- `encoding_rs@0.8.35`

### MIT

- `binstring@0.1.7`
- `bytes@1.11.1`
- `ct-codecs@1.1.6`
- `ed25519-compact@2.2.0`
- `h2@0.3.27`
- `http-body@0.4.6`
- `hyper@0.14.32`
- `juicebox_marshalling@0.3.4`
- `juicebox_networking@0.3.4`
- `juicebox_noise@0.3.4`
- `juicebox_oprf@0.3.4`
- `juicebox_realm_api@0.3.4`
- `juicebox_realm_auth@0.3.4`
- `juicebox_sdk@0.3.4`
- `juicebox_secret_sharing@0.3.4`
- `libm@0.2.16`
- `mio@1.1.1`
- `slab@0.4.12`
- `spin@0.9.8`
- `synstructure@0.13.2`
- `tokio-util@0.7.18`
- `tokio@1.50.0`
- `tower-service@0.3.3`
- `tracing-attributes@0.1.31`
- `tracing-core@0.1.36`
- `tracing@0.1.44`
- `try-lock@0.2.5`
- `want@0.3.1`

### MIT OR Apache-2.0 (used under MIT)

- `anyhow@1.0.102`
- `argon2@0.5.3`
- `async-trait@0.1.89`
- `base64@0.21.7`
- `bitflags@1.3.2`
- `blake2@0.10.6`
- `chacha20poly1305@0.10.1`
- `core-foundation-sys@0.8.7`
- `core-foundation@0.9.4`
- `der@0.6.1`
- `displaydoc@0.2.5`
- `ed25519@2.2.3`
- `equivalent@1.0.2`
- `fnv@1.0.7`
- `form_urlencoded@1.2.2`
- `futures-channel@0.3.32`
- `futures-core@0.3.32`
- `futures-executor@0.3.32`
- `futures-io@0.3.32`
- `futures-macro@0.3.32`
- `futures-sink@0.3.32`
- `futures-task@0.3.32`
- `futures-util@0.3.32`
- `futures@0.3.32`
- `getrandom@0.3.4`
- `half@2.7.1`
- `hashbrown@0.16.1`
- `http@0.2.12`
- `httparse@1.10.1`
- `httpdate@1.0.3`
- `idna@1.1.0`
- `idna_adapter@1.2.1`
- `indexmap@2.13.0`
- `ipnet@2.12.0`
- `k256@0.13.4`
- `lazy_static@1.5.0`
- `mime@0.3.17`
- `num-bigint-dig@0.8.6`
- `num-integer@0.1.46`
- `num-iter@0.1.45`
- `once_cell@1.21.4`
- `p384@0.13.1`
- `password-hash@0.5.0`
- `pem-rfc7468@0.6.0`
- `percent-encoding@2.3.2`
- `pin-project-lite@0.2.17`
- `pkcs1@0.4.1`
- `pkcs8@0.9.0`
- `regex-automata@0.4.14`
- `regex-syntax@0.8.10`
- `regex@1.12.3`
- `reqwest@0.11.27`
- `rsa@0.7.2`
- `serde_urlencoded@0.7.1`
- `signature@1.6.4`
- `smallvec@1.15.1`
- `socket2@0.5.10`
- `socket2@0.6.3`
- `spki@0.6.0`
- `stable_deref_trait@1.2.1`
- `system-configuration-sys@0.5.0`
- `system-configuration@0.5.1`
- `tokio-rustls@0.24.1`
- `url@2.5.8`
- `utf8_iter@1.0.4`

### BSD-2-Clause OR Apache-2.0 OR MIT (used under MIT)

- `zerocopy-derive@0.8.42`

### Unlicense OR MIT (used under MIT)

- `aho-corasick@1.1.4`

### Apache-2.0 OR ISC OR MIT (used under MIT)

- `hyper-rustls@0.24.2`
- `rustls-pemfile@1.0.4`
- `rustls@0.21.12`
- `sct@0.7.1`

### Apache-2.0 OR BSL-1.0 (used under Apache-2.0)

- `ryu@1.0.23`


---

## Other bindings

| Binding | Extra third-party notes |
|---------|-------------------------|
| Python (`chatxdk` wheel) | Embeds the Rust core (+ Juicebox when built with default features). No pure-Python runtime deps. |
| JavaScript/WASM (`@xdevplatform/chat-xdk`) | Embeds the Rust core **without** Juicebox. Optional peer `juicebox-sdk` is separate software. |
| Go (`go/chatxdk`) | Prebuilt static libraries embed the Rust core (+ Juicebox). No Go module dependencies. |
| .NET (`XDevPlatform.ChatXdk`) | Native cdylib embeds the Rust core (+ Juicebox). No NuGet runtime package dependencies. |

---

## Maintaining this file

1. After dependency bumps that change licenses or add non-MIT/Apache crates, update the inventory sections.
2. Keep the **Special notices** section accurate for thrift, subtle, Juicebox, ring, webpki-roots, and Unicode.
3. CI runs `cargo deny check licenses` against [`deny.toml`](deny.toml) to block disallowed licenses.
4. Published packages should include this file next to `LICENSE` (npm, wheels, NuGet, Maven resources, Go module tree).
