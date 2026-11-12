# Ory Hydra v26.2.0: image and source assessment

Prepared by Centipod for the Ory Hydra maintainers, 12 November 2026.

Centipod runs Ory Hydra v26.2.0 in production behind id.centipod.io. Before patching our own deployment we assessed the published image and the source of the release, and we would like to share what we found. Every finding below includes the evidence, so you can check it yourselves. We have not opened any issue or pull request; the patched branches are public in our fork and you are welcome to take anything from them.

## 1. Scope and method

| Item | Value |
|---|---|
| Release | Ory Hydra v26.2.0 (20 March 2026), tag commit `0b84568fffccf151dc5e6c7955fdfb738555bf4b` |
| Image | `oryd/hydra:v26.2.0@sha256:ff67c7fb5f95074fa53374d41151713554960504b340cd3f95b09e65deaea2a9` (Alpine 3.21.6, Go 1.26.0, built from `.docker/Dockerfile-alpine` by the xgoreleaser template) |
| Compared against | `ory/hydra` master at `4174065f` (29 July 2026) |
| Image scanner | Trivy 0.72.0, `--scanners vuln`, local vulnerability database updated 12 November 2026 07:01 UTC |
| Source analysis | Centipod AI Quality Framework 9.7.0, Go rules, `service` profile, all 824 Go files of the tag (911 findings, plus gofmt, go vet and staticcheck output) |
| Verification | `go build`, `go vet`, `go test -short` on the patched trees, an image rebuilt with Ory's Dockerfile, a rescan, and a smoke test against PostgreSQL 16 |

What we did not do: no dynamic testing or penetration testing, no fuzzing, no review of the code outside the findings we triaged, and none of the database-backed test suites for MySQL or CockroachDB. The OIDC conformance, Cypress end-to-end and HSM suites were not run. Only the linux/amd64 image was rebuilt.

The quality framework uses pattern-based detectors. Its own documentation warns that a sizeable share of findings are false positives, so every theme below says what we checked by hand and what we discarded.

## 2. Summary

Three things matter most. First, the published v26.2.0 image carries 4 CRITICAL and 75 HIGH findings: Alpine 3.21.6 packages (OpenSSL 3.3.6, musl, zlib), the Go 1.26.0 standard library, and dependencies such as pgx v5.7.5. Master already fixes most of the Go dependencies but has not been released. With dependency, toolchain and base image changes only, and no change to Hydra's behaviour, we brought the same release down to 0 CRITICAL and 4 HIGH. Second, the CVE scan workflow scans the image built from `.docker/Dockerfile-local-build` (distroless, with a freshly compiled binary), not the published Alpine image, and it does not run on a schedule. This is how the published tag came to collect these findings without CI noticing. Third, a few issues remain on master as well: `go-jose/v3` has no fix for CVE-2026-116587 (JWK parsing denial of service, fixed only in v4.1.6); the server binary links test-only packages, including a Docker API client, through `ory/x/dbal`; and a stored PBKDF2 hash with an empty digest is accepted for any secret with `x/crypto` before v0.52.0, and makes the comparison panic with later versions.

## 3. Image findings

### 3.1 Counts per severity

| Target | Critical | High | Medium | Low | Unknown | Total |
|---|---:|---:|---:|---:|---:|---:|
| v26.2.0 Alpine 3.21.6 packages | 2 | 18 | 32 | 16 | 0 | 68 |
| v26.2.0 `/usr/bin/hydra` (Go 1.26.0) | 2 | 57 | 38 | 8 | 3 | 108 |
| **v26.2.0 image total** | **4** | **75** | **70** | **24** | **3** | **176** |
| Patched Alpine 3.24.4 packages | 0 | 0 | 1 | 0 | 0 | 1 |
| Patched `/usr/bin/hydra` (Go 1.26.11) | 0 | 4 | 4 | 4 | 1 | 13 |
| **Patched image total** | **0** | **4** | **5** | **4** | **1** | **14** |

The patched image is `centipod/hydra:v26.2.0-centipod.1`, built from branch `centipod/v26.2.0-security` as described in section 5.

### 3.2 CRITICAL and HIGH findings by component

The full list of all 79 CRITICAL and HIGH findings, one row per vulnerability, is in the appendix. In summary:

| Component | Installed | Findings | Fixed in | On master |
|---|---|---|---|---|
| libcrypto3, libssl3 (OpenSSL) | 3.3.6-r0 | 2 Critical (CVE-2026-31789), 12 High | 3.3.7-r0 to 3.3.7-r2 | Not fixed in source: `Dockerfile-alpine` still uses `alpine:3.21` |
| musl, musl-utils | 1.2.5-r9 | 4 High | 1.2.5-r11, 1.2.5-r12 | As above |
| zlib | 1.3.1-r2 | 2 High | 1.3.2-r0, 1.3.2-r1 | As above |
| Go standard library | 1.26.0 | 26 High | 1.26.1 to 1.26.10 | Not pinned: `go.mod` has no `toolchain` line, so the patch level depends on the release runner |
| github.com/jackc/pgx/v5 | v5.7.5 | 2 Critical (CVE-2026-33815, CVE-2026-33816) | 5.9.0 | Yes, v5.10.0 |
| golang.org/x/net | v0.48.0 | 7 High | 0.53.0 to 0.62.0 | Partly: v0.56.0 still has CVE-2026-78661 and CVE-2026-78669 |
| golang.org/x/crypto | v0.46.0 | 10 High, all in `x/crypto/ssh` | 0.52.0, 0.55.0 | Partly: v0.53.0 still has CVE-2026-56854 |
| golang.org/x/text | v0.32.0 | 2 High | 0.39.0, 0.41.0 | Partly: v0.39.0 still has CVE-2026-56851 |
| golang.org/x/mod | v0.30.0 | 2 High | 0.40.0 | No: v0.37.0 |
| google.golang.org/grpc | v1.79.3 | 3 High | 1.82.1, 1.82.2, 1.83.1 | Partly: v1.82.1 still has CVE-2026-84304 and CVE-2026-84445 |
| go.opentelemetry.io/otel, otel/sdk | v1.40.0 | 2 High | 1.41.0, 1.43.0 | Yes, v1.44.0 |
| github.com/go-jose/go-jose/v3 | v3.0.4 | 2 High | 3.0.5 for CVE-2026-34986; none on v3 for CVE-2026-116587 | Partly: v3.0.5, CVE-2026-116587 remains |
| github.com/docker/docker | v28.3.3+incompatible | 2 High | none for the +incompatible module | Yes: replaced by `moby/moby/client` |
| github.com/jackc/pgproto3/v2 | v2.3.3 | 1 High | none | Yes: `jackc/pgconn` dependency removed |

We checked the master column by building master (CGO disabled, `-tags json1`) and scanning the binary with the same Trivy database. Master still reports 9 HIGH: go-jose v3 (1), x/crypto (1), x/mod (2), x/net (2), x/text (1) and grpc (2). The Alpine and standard library rows depend on how a release is built, not on master's dependencies.

### 3.3 What remains after patching, and why

| Finding | Why it remains | Exposure in Hydra |
|---|---|---|
| go-jose/v3 v3.0.5, CVE-2026-116587 (High) | Fixed only in go-jose/v4 v4.1.6. Hydra imports go-jose/v3 directly in about 40 non-test files (fosite, jwk, oauth2, client, hsm, oryx/josex and others). Moving to v4 changes the signature parsing API and is not a dependency-only change. | Real. Hydra parses JWKs from sources that clients control: the `jwks` field on client registration (including dynamic client registration when it is enabled), keys fetched from `jwks_uri`, and RFC 7523 trust relationships. In v3, `rsaPrivateKey()` calls `rsa.PrivateKey.Validate()` on any JWK that carries `d`, `p` and `q`, without bounds on their size. |
| docker/docker v28.3.3+incompatible, CVE-2026-41567 and CVE-2026-42306 (High) | No fixed version of the +incompatible module. Master's migration to `moby/moby/client` touches `ory/x/sqlcon/dockertest` and is more than a version bump. | False positive in practice: both CVEs concern the Docker daemon, and Hydra links only the API type packages. They are linked at all only because `driver` imports `ory/x/dbal`, which imports `ory/x/sqlcon/dockertest` (test tooling). See 4.1.5. |
| jackc/pgproto3/v2 v2.3.3, CVE-2026-32286 (High) | No fix. Pulled in by `jackc/pgconn` (pgx v4 family) through `ory/x/popx` and `ory/pop/v6`. Master removed it with a code change. | Low: needs a malicious or compromised PostgreSQL server, and the result is a panic. |

Medium and low findings that remain: zlib 1.3.2-r1 (CVE-2026-4738, fixed in 1.4-r0, not yet in Alpine 3.24), docker/docker (2 Medium), go-jose/v3 (2 Medium, no v3 fix), the OpenTelemetry exporters and sdk v1.44.0 (CVE-2026-81870, Low, fixed in 1.45.0) and GO-2026-5932 (Unknown) for the unmaintained `x/crypto/openpgp` package.

### 3.4 Image recommendations

1. Cut a release from master with the remaining changes on our `centipod/upstream-security` branch (section 5.3). On master alone this removes all HIGH findings except go-jose/v3.
2. Scan the image you publish. `cve-scan.yaml` runs `make docker`, which builds `.docker/Dockerfile-local-build` (Makefile line 57). That image has a different base (distroless Debian 12) and a binary compiled with whatever `golang:1.26` resolves to on the day, so neither the Alpine packages nor the release toolchain of the published tag are scanned.
3. Add a scheduled scan of the released tags, for example a weekly `schedule:` trigger that runs Trivy or Grype against `oryd/hydra:<latest tag>`. Republish the image when the base image has fixes. Most of the 20 Alpine findings were fixed in Alpine 3.21 point releases after 20 March 2026, so a rebuild alone would have removed them.
4. Pin the toolchain patch level (`toolchain go1.26.11` in `go.mod`). `actions/setup-go` with `go-version-file` then selects it, and it is recorded in the source rather than taken from the runner.
5. Migrate from go-jose/v3 to go-jose/v4 (v4.1.6 or later). Until then, one possible stopgap is to reject client-supplied JWKs that carry private RSA members (`d`, `p`, `q`, `dp`, `dq`, `qi`) or an oversized `n` before handing them to go-jose. Client keys should only ever be public keys.

## 4. Source findings

The framework reported 911 findings: 315 BLOCKER, 255 MAJOR and 341 MINOR. 208 of them are in the generated SDK under `internal/httpclient`, 226 in the vendored `oryx` tree (of which several packages are not linked into the `hydra` binary) and 69 in CLI commands under `cmd/`. We grouped them by theme. Line numbers refer to tag v26.2.0.

### 4.1 Security-relevant (273 findings)

#### 4.1.1 Response bodies and whole-input reads (90: GO-RRM-006 9, QLT-CFT-010 81)

*Checked by hand:* all 9 GO-RRM-006 findings, and all 31 QLT-CFT-010 findings outside the generated SDK.

* `client/handler.go:436`: `patchOAuth2Client` reads the whole request body with `io.ReadAll(r.Body)` without a limit. Real, on the admin API.
* Found by hand while checking the above: `client/handler.go:164` (`CreateClient`, also used by dynamic client registration on the public port) and `:260`, `:362` and `:762` decode JSON straight from `r.Body` without `http.MaxBytesReader`. A single large JSON string is held in memory in full. The only bound is the server's 5 second `ReadTimeout` from `ory/graceful`. Similarly, the `ParseMultipartForm(1 << 20)` calls at `fosite/access_request_handler.go:57`, `fosite/authorize_request_handler.go:344`, `fosite/introspect.go:33`, `fosite/revoke_handler.go:45` and `oauth2/handler.go:1007` set a memory threshold, not a size limit: multipart file parts above it are written to temporary files.
* `x/oauth2_test_client.go:46` (`GetExpectRedirect`) never closes the response body on success. Real but test-only, although the file is in the non-test package `x` and therefore linked into the server binary (see 4.1.5).
* False positives: `fosite/authorize_request_handler.go:83` reads the `request_uri` response through a 10 MiB `io.LimitReader` set at line 77. Eight of the nine GO-RRM-006 findings (`fosite/authorize_request_handler.go:337`, `consent/csrf.go:59`, `consent/strategy_default.go:77`, `fosite/handler/openid/flow_hybrid.go:33`, `flow_implicit.go:30`, `oryx/logrusx/helper.go:56`, `oryx/cmdx/printing.go:122` and the generated client) mistake `store.Get(r, name)`, `Form.Get` or `Header.Get` for an HTTP GET. The 50 SDK findings read responses that the generated code already closes. The remaining `oryx` findings read operator-supplied files or stdin, or sit in packages that Hydra does not link (`decoderx`, `fetcher`, `proxy`, `jsonnetx`, `jsonnetsecure`, `migratest`).

Outbound responses are well handled: `client/validator.go:255`, `consent/strategy_default.go:751`, `oauth2/token_hook.go:121` and the `request_uri` fetch all apply a `LimitReader`.

*Recommendation:* add a body size limit to inbound JSON endpoints, either per handler with `http.MaxBytesReader` or once in the router middleware, with a configurable default of 1 MiB.

#### 4.1.2 The process-wide `http.DefaultClient` (8: GO-RRM-001 4, GO-IDN-005 4; the same four sites)

*Checked by hand:* all four.

* `cmd/cli/handler_helper.go:24`: the CLI fetches `--pgp-key-url` with `http.DefaultClient`, which has no timeout. Real, CLI only.
* `internal/httpclient/client.go:73`: the generated SDK falls back to `http.DefaultClient`. Real for SDK users; a generator setting.
* `oryx/jwksx/fetcher.go:31` and `oryx/httpx/wait_for.go:19`: not reachable from Hydra. `jwksx` is not linked and `WaitForEndpoint` has no caller.

The server itself uses `RegistrySQL.HTTPClient` (`driver/registry_sql.go:454`): a retrying client with a 30 second timeout, two retries and an optional private IP deny list. That is good practice.

*Recommendation:* give the CLI and the SDK default an explicit client with timeouts.

#### 4.1.3 Context propagation and goroutine lifetime (89: GO-RRM-007 46, GO-RRM-002 27, GO-IDN-004 14, GO-RRM-003 2)

*Checked by hand:* the GO-RRM-007 file list and 6 bodies; all 27 GO-RRM-002 sites; the GO-IDN-004 sites in server code.

* GO-RRM-007 is almost entirely a false positive. It fires on files that declare interfaces with a `ctx` parameter (`fosite/storage.go`, `fosite/hash.go`, `aead/aead.go`, `consent/manager.go` and so on), and on no-op interface implementations such as `fosite/handler/openid/flow_device_auth.go:23`.
* `consent/strategy_default.go:739`: back-channel logout requests run in goroutines on `context.Background()` with the span copied over. This is deliberate, because the notifications must outlive the request, and they are bounded by the 30 second client timeout. Judged justified.
* `oryx/popx/transaction.go:61` (reported as QLT-AGT-001, listed under 4.1.8): on PostgreSQL, serialisation failures (40001) are retried up to 10 times with no delay.
* `oryx/resilience/retry.go:32` uses `time.Sleep` in a startup retry loop, so cancellation is not observed until the sleep ends. Minor.
* Nine GO-RRM-002 and five GO-IDN-004 findings are test helpers in non-test files (`client/manager_test_helpers.go`, `jwk/manager_test_helpers.go`). Five are CLI commands.

*Recommendation:* add exponential backoff with jitter to the popx retry loop, and use a `select` on `ctx.Done()` in `resilience.Retry`.

#### 4.1.4 Secrets and credentials (5: GO-TSP-008 1, QLT-AUT-004 1, QLT-AUT-004a 3), plus two items found by hand

*Checked by hand:* all five.

* False positives: `fosite/config.go:201` is an interface returning `[]byte`, not a secret wrapper. `internal/kratos/fake_kratos.go:24` is a fixture used only by tests. The three test literals (`client/handler_test.go:67`, `:503`, `flow/encoding_test.go:44`) are fixtures.
* Found by hand while investigating a test failure during patching: `oryx/hasherx/hash_comparator.go:99` to `:108` (`ComparePbkdf2`). `decodePbkdf2Hash` takes the key length from the decoded digest and does not reject zero. A stored hash such as `$pbkdf2-sha256$i=1,l=0$c2FsdHNhbHQ$` therefore compares as a match for any secret with golang.org/x/crypto v0.46.0, the version in v26.2.0, because `subtle.ConstantTimeCompare` of two empty slices returns 1. With x/crypto v0.52.0 or later, `pbkdf2.Key` panics on a zero length instead. We confirmed both outcomes with a small test against the v26.2.0 tree. Exploiting it needs write access to the stored hash, so this is defence in depth, not a remotely exploitable flaw. Master has the same code.
* Weak test cryptography, not flagged by the framework: `fosite/internal/gen/key.go:15` and `fosite/authorize_request_handler_oidc_request_test.go:51` generate 1024-bit RSA keys. Test-only, but they fail under FIPS 140-3 mode and are easy to copy into production code. `cmd/server/helper_cert.go:31` computes a SHA-1 thumbprint for the JWK `x5t` member, which RFC 7517 defines, so we judged it justified.

*Recommendation:* in `decodePbkdf2Hash`, return `ErrInvalidHash` when the iterations or the digest length is zero, and add a regression test. Use 2048-bit keys in the test generators.

#### 4.1.5 Test-only code in the production binary (found by hand)

`go list -deps` of the `hydra` main package (tags `sqlite,hsm,json1`) shows that the server binary links:

* `ory/x/sqlcon/dockertest`, `ory/dockertest/v4` and Docker API client packages, through `driver` importing `ory/x/dbal`. At v26.2.0 these are `docker/docker` types; on master they are `moby/moby/client` and `moby/moby/api`.
* `github.com/stretchr/testify/require`, through `x/oauth2_test_client.go` in package `x`.
* `internal/kratos` together with its fake, `fake_kratos.go`.

This adds code and scanner findings (the docker/docker HIGH findings come only from this path) with no runtime use. *Recommendation:* move the dockertest helpers out of `ory/x/dbal` into a package that only tests import, and move test helpers into `_test.go` files or a `testhelpers` package.

#### 4.1.6 Lint suppressions without a reason (41: GO-LSA-005)

*Checked by hand:* `.golangci.yml` and 8 sites.

* `.golangci.yml` enables only `errcheck`, `ineffassign`, `staticcheck` (with SA1019 disabled) and `unused`. `gosec`, `bodyclose` and `nolintlint` are not enabled. The `//nolint:bodyclose` annotations (for example `cmd/cmd_list_clients.go:34`, `cmd/cmd_create_client.go:97`, `cmd/cmd_delete_jwks.go:35`) and the `#nosec` and `nolint:gosec` annotations (for example `fosite/internal/gen/key.go:14`, `internal/kratos/fake_kratos.go:24`, `cmd/server/handler.go:326`) therefore suppress linters that never run, and none of them gives a reason.
* In substance the `bodyclose` suppressions in `cmd/` are correct, because the generated client reads and closes the body itself (`internal/httpclient/api_o_auth2.go:133` to `:135`). The `//nolint:errcheck` annotations on `defer ...Close()` (for example `cmd/cmd_helper_client.go:28`, `consent/strategy_default.go:750`) are the usual idiom.

*Recommendation:* enable `gosec` (excluding tests, as the configuration already anticipates), `bodyclose` and `nolintlint` with `require-explanation: true`, so the existing annotations take effect and must say why.

#### 4.1.7 CI and release supply chain (35: QLT-SUP-006 32, QLT-SUP-007 1, QLT-SUP-010 1, QLT-AIG-006 1)

*Checked by hand:* every workflow file.

* Real: 32 action references use mutable tags or branches. The most sensitive is `ci.yaml:185`, where `ory/ci/releaser@master` receives the GoReleaser key, the cosign password, the Docker Hub credentials and a bot token. Ory controls that action, but a branch reference still means a change there takes effect on the next release without a change in this repository. `cve-scan.yaml` also uses `aquasecurity/trivy-action@master` and `kubescape/github-action@main`.
* Real: `.trivyignore` and `.grype.yml` both ignore CVE-2023-2650 (an OpenSSL issue from 2023) with no reason or expiry. On master `.trivyignore` is gone, but `.grype.yml` keeps the entry.
* Partly a false positive: QLT-SUP-007 says no vulnerability audit runs. In fact `cve-scan.yaml` runs Grype (failing on HIGH), Trivy and Kubescape on pushes, tags and pull requests. The gap is the one described in 3.4: it scans the wrong image and has no schedule.
* False positive: QLT-SUP-010 says no SBOM is produced. The xgoreleaser template runs `cyclonedx-gomod` for each build and attaches the `*.bom.json` files to the release. What is missing is an SBOM or provenance attestation for the container images themselves; cosign currently signs the image manifests only.

*Recommendation:* pin third-party actions, and at least the release action, to a commit SHA, and let Dependabot or Renovate keep them current. Give each ignore entry a reason and a review date. Attach an image SBOM and provenance (`docker buildx build --sbom=true --provenance=true` or `cosign attest`).

#### 4.1.8 Telemetry and load behaviour (5: QLT-PRV-001 2, QLT-AGT-001 1, QLT-AGT-002 1, GO-RRM-004 1)

* QLT-PRV-001: `oryx/otelx/withspan.go:65` is a URL in a comment, a false positive. `oryx/metricsx/middleware.go:246` is Hydra's anonymous usage telemetry (`https://sqa.ory.sh`, configured at `cmd/server/handler.go:300`). It is documented and can be switched off with `sqa.opt_out`, so it is not undisclosed, but it is on by default. Judged a false positive as reported; mentioned for operators who need opt-in.
* QLT-AGT-001: the retry loop in 4.1.3. Real.
* QLT-AGT-002 (no in-flight ceiling) and GO-RRM-004 (no circuit breaker): project-level design checks aimed at client libraries. Judged not applicable to a server.

### 4.2 Maintainability (638 findings)

| Theme | Rules | Count | Hand check |
|---|---|---:|---|
| `else` after `return` | QLT-CFT-005 | 179 | Accurate on the 5 we read, for example `fosite/access_request_handler.go:57` and `:59`, `fosite/authorize_error.go:55`. Style only. |
| Unnamed numeric literals | QLT-CFT-009 | 137 | 62 are in the generated SDK (mostly the `300` status code boundary): false positives. Real duplicate: the `1 << 20` form threshold appears in 7 handlers (listed in 4.1.1). `aead/aesgcm.go:66` (32 for AES-256) is self-explanatory. |
| Long or complex functions | QLT-CFT-001, -002, -003, -004 | 88 | Accurate. Examples: `cmd/cmd_perform_authorization_code.go:125` (144 statements), `fosite/client_with_custom_token_lifespans.go:57` (`GetEffectiveLifespan`, 20 branches), `driver/registry_sql.go:368` (`HealthHandler`, nesting depth 6). 18 are in generated code. |
| Duplicated blocks | QLT-CFT-011 | 47 | Mostly accurate. Example: `client/handler.go:349`, `:648` and `:819` repeat the same dynamic client registration authentication preamble; the `cmd/cmd_delete_*.go` and `cmd/cmd_get_*.go` commands repeat their scaffolding. |
| Commented-out code | QLT-CFT-008 | 12 | Accurate. Example: `consent/strategy_default.go:555` keeps a disabled implicit flow check with a note that it breaks conformance tests. Several in `fosite/handler/oauth2`. |
| API and type shape | GO-IDN-003, GO-IDN-001, GO-TSP-002, GO-TSP-005 | 161 | GO-IDN-003 (64, `net/http` types in exported signatures) is a false positive for an HTTP server and its handlers. GO-IDN-001 (16) fires on `swagger:parameters` structs and on `fosite/pushed_authorize_response.go:12`, which is written through `ToMap()`: false positives. GO-TSP-002 (80): 67 are generated SDK models that call `DisallowUnknownFields()` (for example `internal/httpclient/model_o_auth2_login_request.go:372`), so an SDK user's decoding fails as soon as a newer server adds a field. That is real for SDK compatibility and worth a generator setting. The rest are hand-written `UnmarshalJSON` methods, such as `fosite/errors.go:495`, where dropping unknown fields is intended. |
| Other | QLT-PRF-005, QLT-PRF-003, GO-RRM-008 | 14 | Eager client construction in CLI commands and pagination in the CLI: not applicable. QLT-PRF-003: the `BenchmarkAuthCode` benchmark has no regression gate. |

Staticcheck adds deprecated test setters (SA1019), initialism naming (ST1003) and comment form (ST1020, ST1021) in non-generated code, and two empty branches at `flow/flow.go:381` and `:437` (SA9003) that are worth a look.

### 4.3 False positive rate

We judged roughly 300 of the 911 findings, about one in three, to be false positives or not applicable to a server. Most came from GO-IDN-003, GO-RRM-007, the misread `Get` calls, and findings in generated or unlinked code. A further 150 or so are accurate but sit in generated code, where they are a matter for the generator, not for hand edits. Two of the CI absence checks (vulnerability audit, SBOM) were wrong in their headline claim but still pointed at a real gap.

## 5. What Centipod did

### 5.1 Branch `centipod/v26.2.0-security` (from tag v26.2.0)

Published at https://github.com/centipod/hydra/tree/centipod/v26.2.0-security. Each commit is small and explains itself:

| Commit | Change |
|---|---|
| `780f29cd` | `toolchain go1.26.11` in `go.mod`; builder images of `Dockerfile-local-build` and `Dockerfile-test-hsm` pinned to `golang:1.26.11` (Alpine 3.24 for the HSM image) |
| `c314cdc0` | `go mod tidy` of the root `go.sum` (four unused checksums), so the following diffs stay focused |
| `ca538eff` | pgx/v5 v5.7.5 to v5.10.0 (root and `oryx`) |
| `75d06b5a` | go-jose/v3 v3.0.4 to v3.0.5 |
| `18973247` | OpenTelemetry v1.40.0 to v1.44.0 with matching contrib modules (master's set). `otelhttp.DefaultClient` no longer exists, so `oauth2/oauth2_auth_code_bench_test.go` builds the client the way master does |
| `4a3e02cf` | Backport of master's `60c9371a` (valid PBKDF2 test configuration), needed once x/crypto is v0.52.0 or later |
| `066e7993` | golang.org/x/net v0.62.0, which raises x/crypto to v0.58.0, x/text to v0.43.0 and x/mod to v0.41.0 |
| `0c5d0971` | grpc v1.81.1 to v1.83.2 |
| `3ef22e32` | `Dockerfile-alpine`: `alpine:3.21` to `alpine:3.24` |

A final commit adds this report as `CENTIPOD-ASSESSMENT.md`. No non-test Go source was changed. Inside `oryx` we only ran `go get`, because that copy of ory/x is not tidy at the tag and tidying it would remove unrelated requirements.

### 5.2 Verification

* `go build ./...` (root and `oryx`) and `go vet -tags sqlite,json1 ./...` are clean.
* `go test -short -tags sqlite,json1` on `fosite/...`, `oauth2/...`, `consent/...`, `jwk/...`, `client/...`, `x/...`, `aead`, `flow`, `health`, `persistence/...`, `driver/...`, `cmd/...` and `fositex`: 31 packages pass, none fail, and 11 have no test files. The first run failed in `x` (`TestHasher`, the x/crypto change in 4.1.4), which the backported `60c9371a` fixes. In short mode the registries and persister tests use SQLite and the in-memory store. The PostgreSQL, MySQL and CockroachDB variants were skipped, as were the e2e, conformance and HSM suites.
* Because pgx was the critical update, we also ran the rebuilt image against PostgreSQL 16.15: `hydra migrate sql up` applied 224 migrations; `hydra serve all` became ready; a client was created; `hydra perform client-credentials` returned a token; and introspection reported it active for that client. The server logged no errors.
* Image: the binary was built in `golang:1.26.11-alpine3.24` for linux/amd64 with `CGO_ENABLED=1 -tags=sqlite,hsm,json1 -ldflags "-s -w ..."`, matching the template's `alpine-cgo-amd64` build. It was then copied in with the unchanged `.docker/Dockerfile-alpine` (now `FROM alpine:3.24`) and tagged `centipod/hydra:v26.2.0-centipod.1`.
* Smoke test: `hydra version` reports `v26.2.0-centipod.1` built from `3ef22e32`. The output of `hydra serve all --help` matches the original image, as does `--help` for `serve public`, `serve admin`, `migrate sql up`, `create client`, `perform client-credentials` and `janitor`. The entrypoint, default command and user (`nonroot`, 65532) are also unchanged.
* Trivy: from 4 CRITICAL, 75 HIGH, 70 MEDIUM, 24 LOW and 3 UNKNOWN to 0, 4, 5, 4 and 1 (section 3).

### 5.3 Branch `centipod/upstream-security` (from master `4174065f`)

Published at https://github.com/centipod/hydra/tree/centipod/upstream-security, with only what master still lacks:

| Commit | Change |
|---|---|
| `51592871` | `toolchain go1.26.11`; local build and HSM test builder images pinned to Go 1.26.11 |
| `28f6191c` | `go mod tidy` of the root `go.sum` (the same four entries) |
| `90a600f7` | x/net v0.56.0 to v0.62.0 (x/crypto v0.58.0, x/text v0.43.0, x/mod v0.41.0) |
| `78b17943` | grpc v1.82.1 to v1.83.2 |
| `23ad9638` | `Dockerfile-alpine`: `alpine:3.21` to `alpine:3.24` |

`go build`, `go vet` and the same short test subset pass: 31 packages pass and none fail. A scan of this branch's binary would leave only go-jose/v3 CVE-2026-116587 among the HIGH findings.

## 6. Recommendations, in order of value

1. **Release from master.** v26.2.0 is the newest release, and master has many fixes users cannot get without one. Besides the dependency updates, these include several security-relevant changes, such as a DNS-label boundary for wildcard return URLs and CORS origins (`7f38a72a`), AEAD-sealed keyset pagination tokens (`20ea0ffe`) and a fix for an OIDC session leak in the device authorization grant (`e6a73547`). Apply the five commits of `centipod/upstream-security` first, or equivalent changes.
2. **Scan what you ship, and keep scanning it.** Point `cve-scan.yaml` at the image built from `Dockerfile-alpine` (and the distroless variant), add a scheduled run against the latest released tags, and rebuild when the base image has fixes.
3. **Move to go-jose/v4 (v4.1.6 or later).** This is the only HIGH finding left on master. It is reachable through client-supplied JWKs. A check that rejects private members in client JWKs would be a reasonable stopgap.
4. **Reject degenerate PBKDF2 hashes** (zero iterations or zero digest length) in `ory/x/hasherx` before calling `pbkdf2.Key`.
5. **Remove test-only packages from the server binary** (`ory/x/dbal` to `sqlcon/dockertest`, `x/oauth2_test_client.go`, the Kratos fake). This removes the Docker client and testify from the attack surface and from scanner output.
6. **Limit inbound request bodies** on JSON endpoints, at least on dynamic client registration on the public port.
7. **Pin the release action and third-party scanners by commit SHA**; give scanner ignore entries reasons; publish image SBOMs and provenance.
8. **Enable `gosec`, `bodyclose` and `nolintlint`** so that the existing suppressions take effect and must explain themselves.
9. **Maintainability:** consider a generator setting so the SDK tolerates unknown fields; deduplicate the dynamic client registration handlers and the CLI command scaffolding; name the form memory threshold once; remove commented-out code; split `cmd_perform_authorization_code.go`.

Thank you for Hydra. We are glad to answer questions about any of this, and to rerun the scans against a release candidate.

## Appendix: every CRITICAL and HIGH finding in the v26.2.0 image

"Patched branch" refers to `centipod/v26.2.0-security`. "Master" is the state at `4174065f`, with the master version in brackets where relevant.

| Severity | Package | Vulnerability | Installed | Fixed in | Patched branch | Master |
|---|---|---|---|---|---|---|
| Critical | jackc/pgx/v5 | CVE-2026-33815 | v5.7.5 | 5.9.0 | fixed | yes (v5.10.0) |
| Critical | jackc/pgx/v5 | CVE-2026-33816 | v5.7.5 | 5.9.0 | fixed | yes (v5.10.0) |
| Critical | libcrypto3 | CVE-2026-31789 | 3.3.6-r0 | 3.3.7-r0 | fixed | no: Dockerfile still on alpine:3.21 |
| Critical | libssl3 | CVE-2026-31789 | 3.3.6-r0 | 3.3.7-r0 | fixed | no: Dockerfile still on alpine:3.21 |
| High | docker/docker | CVE-2026-41567 | v28.3.3+incompatible | none | remains | yes: replaced by moby/moby |
| High | docker/docker | CVE-2026-42306 | v28.3.3+incompatible | none | remains | yes: replaced by moby/moby |
| High | go-jose/go-jose/v3 | CVE-2026-116587 | v3.0.4 | none | remains | no (v3.0.5) |
| High | go-jose/go-jose/v3 | CVE-2026-34986 | v3.0.4 | 3.0.5 | fixed | yes (v3.0.5) |
| High | grpc | CVE-2026-84304 | v1.79.3 | 1.83.1 | fixed | no (v1.82.1) |
| High | grpc | CVE-2026-84445 | v1.79.3 | 1.82.2 | fixed | no (v1.82.1) |
| High | grpc | GHSA-hrxh-6v49-42gf | v1.79.3 | 1.82.1 | fixed | yes (v1.82.1) |
| High | jackc/pgproto3/v2 | CVE-2026-32286 | v2.3.3 | none | remains | yes: dependency removed |
| High | libcrypto3 | CVE-2026-28387 | 3.3.6-r0 | 3.3.7-r0 | fixed | no: Dockerfile still on alpine:3.21 |
| High | libcrypto3 | CVE-2026-28388 | 3.3.6-r0 | 3.3.7-r0 | fixed | no: Dockerfile still on alpine:3.21 |
| High | libcrypto3 | CVE-2026-28389 | 3.3.6-r0 | 3.3.7-r0 | fixed | no: Dockerfile still on alpine:3.21 |
| High | libcrypto3 | CVE-2026-28390 | 3.3.6-r0 | 3.3.7-r0 | fixed | no: Dockerfile still on alpine:3.21 |
| High | libcrypto3 | CVE-2026-45447 | 3.3.6-r0 | 3.3.7-r1 | fixed | no: Dockerfile still on alpine:3.21 |
| High | libcrypto3 | CVE-2026-84782 | 3.3.6-r0 | 3.3.7-r2 | fixed | no: Dockerfile still on alpine:3.21 |
| High | libssl3 | CVE-2026-28387 | 3.3.6-r0 | 3.3.7-r0 | fixed | no: Dockerfile still on alpine:3.21 |
| High | libssl3 | CVE-2026-28388 | 3.3.6-r0 | 3.3.7-r0 | fixed | no: Dockerfile still on alpine:3.21 |
| High | libssl3 | CVE-2026-28389 | 3.3.6-r0 | 3.3.7-r0 | fixed | no: Dockerfile still on alpine:3.21 |
| High | libssl3 | CVE-2026-28390 | 3.3.6-r0 | 3.3.7-r0 | fixed | no: Dockerfile still on alpine:3.21 |
| High | libssl3 | CVE-2026-45447 | 3.3.6-r0 | 3.3.7-r1 | fixed | no: Dockerfile still on alpine:3.21 |
| High | libssl3 | CVE-2026-84782 | 3.3.6-r0 | 3.3.7-r2 | fixed | no: Dockerfile still on alpine:3.21 |
| High | musl | CVE-2026-107891 | 1.2.5-r9 | 1.2.5-r12 | fixed | no: Dockerfile still on alpine:3.21 |
| High | musl | CVE-2026-40200 | 1.2.5-r9 | 1.2.5-r11 | fixed | no: Dockerfile still on alpine:3.21 |
| High | musl-utils | CVE-2026-107891 | 1.2.5-r9 | 1.2.5-r12 | fixed | no: Dockerfile still on alpine:3.21 |
| High | musl-utils | CVE-2026-40200 | 1.2.5-r9 | 1.2.5-r11 | fixed | no: Dockerfile still on alpine:3.21 |
| High | otel | CVE-2026-29181 | v1.40.0 | 1.41.0 | fixed | yes (v1.44.0) |
| High | otel/sdk | CVE-2026-39883 | v1.40.0 | 1.43.0 | fixed | yes (v1.44.0) |
| High | stdlib | CVE-2026-111943 | v1.26.0 | 1.26.10, 1.27.3 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-25679 | v1.26.0 | 1.25.8, 1.26.1 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-27137 | v1.26.0 | 1.26.1 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-27145 | v1.26.0 | 1.25.11, 1.26.4 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-32280 | v1.26.0 | 1.25.9, 1.26.2 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-32281 | v1.26.0 | 1.25.9, 1.26.2 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-32283 | v1.26.0 | 1.25.9, 1.26.2 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-33810 | v1.26.0 | 1.26.2 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-33811 | v1.26.0 | 1.25.10, 1.26.3 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-33814 | v1.26.0 | 1.25.10, 1.26.3 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-33818 | v1.26.0 | 1.25.13, 1.26.6, 1.27.0-rc.3 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-39820 | v1.26.0 | 1.25.10, 1.26.3 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-39821 | v1.26.0 | 1.25.13, 1.26.6, 1.27.0-rc.3 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-39822 | v1.26.0 | 1.25.12, 1.26.5, 1.27.0-rc.2 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-39836 | v1.26.0 | 1.25.10, 1.26.3 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-42499 | v1.26.0 | 1.25.10, 1.26.3 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-42504 | v1.26.0 | 1.25.11, 1.26.4 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-46600 | v1.26.0 | 1.26.6, 1.27.0-rc.3 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-56853 | v1.26.0 | 1.25.13, 1.26.6, 1.27.0-rc.3 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-56858 | v1.26.0 | 1.25.13, 1.26.6, 1.27.0-rc.3 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-56859 | v1.26.0 | 1.25.13, 1.26.6, 1.27.0-rc.3 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-56860 | v1.26.0 | 1.25.13, 1.26.6, 1.27.0-rc.3 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-56862 | v1.26.0 | 1.25.13, 1.26.6, 1.27.0-rc.3 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-78667 | v1.26.0 | 1.26.9, 1.27.2 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-78669 | v1.26.0 | 1.26.9, 1.27.2 | fixed | not pinned: depends on the release toolchain |
| High | stdlib | CVE-2026-97031 | v1.26.0 | 1.26.9, 1.27.2 | fixed | not pinned: depends on the release toolchain |
| High | x/crypto | CVE-2026-39828 | v0.46.0 | 0.52.0 | fixed | yes (v0.53.0) |
| High | x/crypto | CVE-2026-39829 | v0.46.0 | 0.52.0 | fixed | yes (v0.53.0) |
| High | x/crypto | CVE-2026-39830 | v0.46.0 | 0.52.0 | fixed | yes (v0.53.0) |
| High | x/crypto | CVE-2026-39831 | v0.46.0 | 0.52.0 | fixed | yes (v0.53.0) |
| High | x/crypto | CVE-2026-39832 | v0.46.0 | 0.52.0 | fixed | yes (v0.53.0) |
| High | x/crypto | CVE-2026-39835 | v0.46.0 | 0.52.0 | fixed | yes (v0.53.0) |
| High | x/crypto | CVE-2026-42508 | v0.46.0 | 0.52.0 | fixed | yes (v0.53.0) |
| High | x/crypto | CVE-2026-46595 | v0.46.0 | 0.52.0 | fixed | yes (v0.53.0) |
| High | x/crypto | CVE-2026-46597 | v0.46.0 | 0.52.0 | fixed | yes (v0.53.0) |
| High | x/crypto | CVE-2026-56854 | v0.46.0 | 0.55.0 | fixed | no (v0.53.0) |
| High | x/mod | CVE-2026-56864 | v0.30.0 | 0.40.0 | fixed | no (v0.37.0) |
| High | x/mod | CVE-2026-56865 | v0.30.0 | 0.40.0 | fixed | no (v0.37.0) |
| High | x/net | CVE-2026-25681 | v0.48.0 | 0.55.0 | fixed | yes (v0.56.0) |
| High | x/net | CVE-2026-27136 | v0.48.0 | 0.55.0 | fixed | yes (v0.56.0) |
| High | x/net | CVE-2026-33814 | v0.48.0 | 0.53.0 | fixed | yes (v0.56.0) |
| High | x/net | CVE-2026-39821 | v0.48.0 | 0.55.0 | fixed | yes (v0.56.0) |
| High | x/net | CVE-2026-46600 | v0.48.0 | 0.56.0 | fixed | yes (v0.56.0) |
| High | x/net | CVE-2026-78661 | v0.48.0 | 0.62.0 | fixed | no (v0.56.0) |
| High | x/net | CVE-2026-78669 | v0.48.0 | 0.60.0 | fixed | no (v0.56.0) |
| High | x/text | CVE-2026-56851 | v0.32.0 | 0.41.0 | fixed | no (v0.39.0) |
| High | x/text | CVE-2026-56852 | v0.32.0 | 0.39.0 | fixed | yes (v0.39.0) |
| High | zlib | CVE-2026-22184 | 1.3.1-r2 | 1.3.2-r0 | fixed | no: Dockerfile still on alpine:3.21 |
| High | zlib | CVE-2026-85091 | 1.3.1-r2 | 1.3.2-r1 | fixed | no: Dockerfile still on alpine:3.21 |
