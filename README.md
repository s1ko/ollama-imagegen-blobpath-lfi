# ollama: unvalidated manifest digest in the tensor-model pull path (`BlobPath` file read, `Download` early-exit)

When Ollama pulls a tensor-format (safetensors) model, it takes the layer
digests from the registry's manifest and turns them into filesystem paths
without checking that they are digests. A registry that serves a digest such as
`sha256:../../../../id_ed25519` makes two pieces of code resolve a path outside
the blob directory: the download step's "already cached" check
(`os.Stat` + size compare, which then skips the network fetch and lets the
manifest be committed), and `ModelManifest.BlobPath`, which the model loader later
passes to `os.ReadFile` / `os.Open`. The result is an arbitrary-path file open in
the Ollama server process and a file-existence-and-size oracle for the registry
operator. It does not, by itself, return file contents to the attacker.

| | |
|---|---|
| CVE | none assigned to this finding. The sibling `digestToPath` write-side issue is [CVE-2026-7020](https://github.com/advisories/GHSA-x99g-8v8j-25j2) / GHSA-x99g-8v8j-25j2 — see [Prior coverage](#prior-coverage) |
| CWE | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) |
| Project | [`ollama/ollama`](https://github.com/ollama/ollama) |
| Affected | v0.14.0 (2026-01-13) through v0.34.1 for the `BlobPath` read side; through v0.34.4 for the download-side early-exit. Pulls of tensor models only |
| Fixed in | v0.34.2 (read side removed, `d27fde67ea`, 2026-09-16); v0.35.0 (digests validated before download, `cc4069396f`, 2026-09-28) |
| CVSS v3.1 | `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` = **3.1 Low** |
| Reported by | s1ko ([github.com/s1ko](https://github.com/s1ko), `s1ko@riseup.net`) |

## Scope, stated plainly

- **Trigger.** The victim must run `ollama pull` against a registry the attacker
  controls (or can man-in-the-middle; plain-HTTP registries need `--insecure`).
  Only manifests that contain at least one layer with media type
  `application/vnd.ollama.image.tensor` are routed to the vulnerable code; the
  ordinary GGUF pull path validates digests with `manifest.BlobsPath`. From
  v0.32.10 such a pull additionally requires the MLX runtime to initialise
  (`88313499e`, "avoid pulling MLX models when MLX is missing"), which narrows the
  population to MLX-capable hosts.
- **What the read side gives.** `BlobPath` feeds `os.ReadFile` / `os.Open` in the
  model loaders (`ReadConfig`, the tensor-header scan, `mlx.Load`). The bytes are
  parsed as JSON or safetensors and discarded. Nothing in the call chain echoes
  them to the registry operator, so **this is not file exfiltration**. The earlier
  submission of this finding scored it as key theft (7.7 High); that is not what
  the code does, and the score here reflects it.
- **What the registry operator can observe.** If the traversal path exists and
  its size equals the manifest's `size`, the downloader skips the blob and never
  requests it. If it does not match, the registry sees a `GET` for that digest.
  That is an existence-and-exact-size oracle for arbitrary paths on the victim.
  The failed-match branch is where the write-side bug, CVE-2026-7020, lives.
- **Corrections to the original submission**, so that anyone comparing the two
  texts is not misled: the example manifest there has no tensor layer and would
  not reach this code path; the Ollama-generated `~/.ollama/id_ed25519` is **387**
  bytes with the code at v0.34.1 and at `ea01af6f` (measured by running
  `ssh.MarshalPrivateKey(key, "")` + `pem.EncodeToMemory` from `cmd/cmd.go`), not
  399; and the vulnerable range starts at v0.14.0, not v0.5.x.
- **Tested at unit level.** The PoC drives `ModelManifest` and
  `transfer.Download` directly. It was not chained into a single end-to-end pull
  against a live MLX-enabled server for this advisory.

## Threat model

The registry named in `ollama pull host/namespace/model` is untrusted input. A
malicious registry, a compromised one, or a network attacker on an `--insecure`
connection chooses every field of the manifest it returns. The manifest is
parsed into `manifest.Layer` values and handed to the transfer package without a
digest-format check, so the digest string is attacker-chosen text that becomes a
path component.

The traversal arithmetic, with the blob directory at `~/.ollama/models/blobs`:
`digestToPath` / `BlobPath` replace the first `:` with `-`, so `sha256:` becomes
the literal directory name `sha256-..`, which the first `..` then cancels.

| Digest | Resolves to |
|---|---|
| `sha256:../../../../id_ed25519` | `~/.ollama/id_ed25519` |
| `sha256:../../../../../.ssh/id_rsa` | `~/.ssh/id_rsa` |
| `sha256:../../../../../../../etc/passwd` | `/etc/passwd` |

## Execution

All excerpts are verbatim from tag v0.34.1 (`38fdb5dd58c761f850cddd6ba1e78a7954646b4f`),
the last release that carries both halves.

**1. The pull is routed to the fast path by any tensor layer**
(`server/images.go:1052`, `1140-1147`):

```go
	if hasTensorLayers(layers) {
		if err := pullWithTransfer(ctx, n, layers, manifestData, regOpts, fn); err != nil {
```

```go
func hasTensorLayers(layers []manifest.Layer) bool {
	for _, layer := range layers {
		if layer.MediaType == manifest.MediaTypeImageTensor {
			return true
		}
	}
	return false
}
```

`pullWithTransfer` (`server/images.go:1150-1157`) copies each `layer.Digest`
straight into a `transfer.Blob`, calls `transfer.Download` (`:1192`), and then
writes the registry's manifest to disk (`:1217`).

**2. The early-exit trusts the digest as a path** (`x/transfer/download.go:105-112`):

```go
	for _, b := range opts.Blobs {
		if fi, _ := os.Stat(filepath.Join(opts.DestDir, digestToPath(b.Digest))); fi != nil && fi.Size() == b.Size {
			if opts.Logger != nil {
				opts.Logger.Debug("blob already exists", "digest", b.Digest, "size", b.Size)
			}
			alreadyCompleted += b.Size
			continue
		}
```

`digestToPath` (`x/transfer/transfer.go:171-176`) only rewrites the separator:

```go
func digestToPath(digest string) string {
	if len(digest) > 7 && digest[6] == ':' {
		return digest[:6] + "-" + digest[7:]
	}
	return digest
}
```

When every blob is "already there", `download` returns `nil` and `pullWithTransfer`
commits the manifest containing the traversal digest.

**3. The read side** (`x/imagegen/manifest/manifest.go:100-105`, `135-143`, `155-157`):

```go
func (m *ModelManifest) BlobPath(digest string) string {
	// Convert "sha256:abc123" to "sha256-abc123"
	blobName := strings.Replace(digest, ":", "-", 1)
	return filepath.Join(m.BlobDir, blobName)
}
```

```go
	blobPath := m.BlobPath(layer.Digest)
	return os.ReadFile(blobPath)
```

```go
func (m *ModelManifest) OpenBlob(digest string) (io.ReadCloser, error) {
	return os.Open(m.BlobPath(digest))
}
```

At v0.34.1 these are reached from the MLX runner when it loads the model:
`x/mlxrunner/model/root.go:51` (tensor-header scan), `:79` (config layer),
`x/mlxrunner/runner.go:243-244` (`mlx.Load(blobPath)`), and the per-architecture
loaders' `root.Manifest.ReadConfig("config.json")` / `tokenizer.json` calls.

The validated equivalent already existed in the standard pull path:
`manifest.BlobsPath` rejects anything that is not `^sha256[:-][0-9a-fA-F]{64}$`.

### Reproduction

Go toolchain required. [`poc/poc_blobpath_test.go`](poc/poc_blobpath_test.go)
exercises `BlobPath`, `ReadConfig` and `OpenBlob`;
[`poc/poc_download_test.go`](poc/poc_download_test.go) exercises
`transfer.Download` against an `httptest` server and counts requests.
[`poc/run-poc.sh`](poc/run-poc.sh) copies them into whichever of
`x/imagegen/transfer`, `x/transfer` or `transfer` exists in the checkout, runs
them, and removes them again.

```
git clone https://github.com/ollama/ollama
cd ollama
git checkout v0.34.1
bash /path/to/poc/run-poc.sh .
```

Five tests pass on an affected tree, which means the behaviour is present
([`expected-output-v0.34.1.txt`](poc/expected-output-v0.34.1.txt)):

```
--- PASS: TestPoC_BlobPath_ResolvesOutsideBlobDir (0.00s)
--- PASS: TestPoC_ReadConfig_LFI_ViaTraversalDigest (0.00s)
--- PASS: TestPoC_OpenBlob_LFI_ViaTraversalDigest (0.00s)
--- PASS: TestPoC_Download_EarlyExitCacheBypass_AcceptsTraversalDigest (0.00s)
--- PASS: TestPoC_Download_EarlyExitChainEndState (0.00s)
```

Results measured on 2026-10-28:

| Tag / commit | `x/imagegen/manifest` | Download tests | Reading |
|---|---|---|---|
| `ea01af6f` (v0.21.3-rc0, report time) | present | 2 pass | both halves vulnerable ([output](poc/expected-output-ea01af6f.txt)) |
| v0.34.1 | present | 2 pass | both halves vulnerable ([output](poc/expected-output-v0.34.1.txt)) |
| v0.34.4 | gone | 2 pass | read side removed, download side still accepts the digest ([output](poc/expected-output-v0.34.4.txt)) |
| v0.35.0 | gone | 2 fail | `Download` returns `invalid digest format` ([output](poc/expected-output-v0.35.0.txt)) |

The v0.35.0 failures are the fix working: the tests assert the vulnerable
behaviour, so they fail once `Download` rejects the digest.

## Detection

A manifest written by an affected pull stays on disk. Any layer or config digest
that is not a plain SHA-256 digest is the indicator. This lists them
(manifests live under `$OLLAMA_MODELS/manifests`, default `~/.ollama/models/manifests`):

```
find "${OLLAMA_MODELS:-$HOME/.ollama/models}/manifests" -type f -exec jq -r \
  'input_filename as $f | [.config.digest, (.layers[]?.digest)][]
   | select(test("^sha256[:-][0-9a-fA-F]{64}$") | not) | "\($f): \(.)"' {} +
```

A hit means a registry served a digest that cannot be a SHA-256 value; delete
that model and treat the registry as hostile. The same check run against
registry responses (a proxy, or `--insecure` plain HTTP captures) catches the
attack before the pull completes.

YARA, for scanning a manifest directory:

```
rule ollama_manifest_traversal_digest
{
    meta:
        description = "Ollama manifest with a path-traversal sequence in a layer or config digest"
        author = "s1ko"
        reference = "CWE-22"
    strings:
        $digest = /"digest"\s*:\s*"sha256[:-][^"]*(\.\.|\/|\\)[^"]*"/
    condition:
        $digest
}
```

Semgrep, for the code pattern in a Go tree (a digest turned into a path with only
the separator rewritten):

```
rules:
  - id: digest-to-path-without-validation
    languages: [go]
    severity: WARNING
    message: digest rewritten into a path component without matching ^sha256[:-][0-9a-f]{64}$
    pattern-either:
      - pattern: |
          $X := strings.Replace($D, ":", "-", 1)
          ...
          filepath.Join($DIR, $X)
      - pattern: return $D[:6] + "-" + $D[7:]
```

Both rules were run against v0.34.1: the Semgrep rule flags `BlobPath` and
`digestToPath`, and the YARA rule matches a manifest carrying
`sha256:../../../../id_ed25519` and not one with a well-formed digest.

Runtime signal: an Ollama server that opens a path outside `models/blobs` while
loading a model. `strace -f -e trace=openat -p <ollama pid>` during the load of a
suspect model shows an `openat` of something that is not a blob digest, such as
`~/.ollama/id_ed25519`.

## Mitigation

- **Upgrade to v0.35.0 or later.** `transfer.Download` and `transfer.Upload` call
  `validateBlobs` -> `manifest.ValidateDigest` before any filesystem use, and the
  `x/imagegen/manifest` package no longer exists. v0.34.2 to v0.34.4 have the
  read side removed but not the download-side validation.
- Do not pull safetensors / tensor-format models from registries you do not
  control, and do not use `--insecure` against anything but a loopback registry.
- Audit existing manifests with the `jq` command above.
- For code that builds paths from a content digest: match the whole string
  against `^sha256[:-][0-9a-fA-F]{64}$` before use, and treat a non-match as an
  error rather than as a cache miss.

NIST SP 800-53r5 `SI-10`; OWASP ASVS v4 §12.3.1; CWE-22 mitigation (allowlist
the digest format); MITRE ATT&CK T1005 for the read primitive.

## Timeline

| Date | Event |
|---|---|
| 2026-01-09 | `ModelManifest.BlobPath` added with the image-generation prototype (`25849400`); first release containing it is v0.14.0 (2026-01-13) |
| 2026-04-25 | Reported via huntr.com (report `69b812da-12b4-45c1-b110-8f629b9513c0`), verified against `ea01af6f` (v0.21.3-rc0). The platform acknowledged it and passed it to internal triage, notified the vendor and marked it published (2026-07-24) without ever validating it; no bounty or credit as of 2026-10-28. |
| 2026-04-26 | CVE-2026-7020 / GHSA-x99g-8v8j-25j2 published for `digestToPath` (a different impact, see below) |
| 2026-05-05 | `x/imagegen/transfer` moved to `x/transfer` (`2d84ec93`); first in v0.23.2 |
| 2026-07-14 / 07-16 | Public issue [#17178](https://github.com/ollama/ollama/issues/17178) and PR [#17214](https://github.com/ollama/ollama/pull/17214) on `digestToPath` (write side) |
| 2026-09-16 | `x/imagegen/manifest` removed (`d27fde67ea`, "mlxrunner: read model manifests through the manifest package"); first in v0.34.2 |
| 2026-09-28 | `validateBlobs` added to `transfer.Download` / `Upload` (`cc4069396f`, #18625); first in v0.35.0 |
| 2026-10-28 | Published here |

The commit messages of the two fixes describe a refactor and a stall-retry
change; neither mentions this issue, and this advisory does not suggest that
either was made in response to it.

## Prior coverage

- **CVE-2026-7020 / GHSA-x99g-8v8j-25j2**, published 2026-04-26 (one day after
  the report above), "Ollama up to 0.20.2 ... function `digestToPath` of the file
  `x/imagegen/transfer/transfer.go`". It is the same input, an unvalidated digest,
  in the same download package, and the
  [public write-up](https://github.com/ollama/ollama/issues/17178) of it
  (2026-07-14) describes the *write* consequence: `os.MkdirAll` and `os.Create`
  at the traversal path before any hash check. It does not describe the
  `os.Stat` early-exit as a cache bypass, and it does not cover
  `ModelManifest.BlobPath` or the read sinks. The v0.35.0 validation closes both.
  This finding is independent of that advisory; the report date precedes the
  advisory's publication date by one day.
- PR #17214 proposes digest validation in `x/transfer` for the write side; it was
  open and unmerged on 2026-10-28.
- No GHSA or issue on `ollama/ollama` mentions `BlobPath`.

## References

- Affected tag — https://github.com/ollama/ollama/tree/v0.34.1
- Read side removed — https://github.com/ollama/ollama/commit/d27fde67eada546a96dc00758645322cbe087802
- Download-side validation — https://github.com/ollama/ollama/commit/cc4069396f3ad2c370c53eed2e4a42ac13adab84
- CVE-2026-7020 — https://github.com/advisories/GHSA-x99g-8v8j-25j2
- Issue #17178 — https://github.com/ollama/ollama/issues/17178

## License

MIT — see [LICENSE](LICENSE).
