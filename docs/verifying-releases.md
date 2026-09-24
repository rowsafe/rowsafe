# Verifying releases

The Rowsafe agent runs as the `postgres` user on your database servers, so you should be able to prove that the binary you run is the one built from this repository. Every release carries four independent proofs. You don't need any of them for normal use: the installer and the agent check the first one automatically.

| Proof | What it shows | Checked by |
|---|---|---|
| **Ed25519 manifest signature** (`manifest.json.sig`) | Rowsafe published this release | the installer and the agent, before installing or updating, using a public key compiled into them |
| **SLSA build provenance** (Sigstore) | GitHub Actions built each file from this repository, at this tag, with this workflow | you, with `gh` or `cosign` |
| **SBOM** (SPDX, attested) | every dependency compiled into the binaries | you, or your vulnerability scanner |
| **Reproducible build** | the published binaries are exactly what the source produces | you, by rebuilding; CI does it on every release |

Provenance and SBOM attestations are signed keylessly with [Sigstore](https://www.sigstore.dev) and recorded in its public transparency log (Rekor), so they can't be quietly replaced.

## 1. Build provenance (quickest)

With the [GitHub CLI](https://cli.github.com):

```sh
gh release download v1.2.3 -R rowsafe/rowsafe -p 'rowsafe-agent-linux-amd64'
gh attestation verify rowsafe-agent-linux-amd64 --repo rowsafe/rowsafe
```

The output names the workflow (`.github/workflows/release.yml`), the tag and the commit that produced the file.

## 2. Checksums

```sh
gh release download v1.2.3 -R rowsafe/rowsafe -p SHA256SUMS -p 'rowsafe-*'
gh attestation verify SHA256SUMS --repo rowsafe/rowsafe
sha256sum --check --ignore-missing SHA256SUMS
```

## 3. The Ed25519 manifest signature

This is the check the agent itself makes before every update. The public key is published with each release (and compiled into every agent):

```sh
curl -fsSLO https://releases.rowsafe.sh/agent/1.2.3/manifest.json
curl -fsSLO https://releases.rowsafe.sh/agent/1.2.3/manifest.json.sig
rowsafe-release verify --public-key <RELEASE_PUBLIC_KEY> manifest.json manifest.json.sig
```

## 4. Docker images

Images are signed with cosign (keyless) and carry provenance and an SBOM:

```sh
cosign verify ghcr.io/rowsafe/agent:1.2.3-pg17 \
  --certificate-identity-regexp '^https://github.com/rowsafe/rowsafe/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify oci://ghcr.io/rowsafe/agent:1.2.3-pg17 --repo rowsafe/rowsafe
```

## 5. Rebuild it yourself

Release builds are reproducible: CGO is off, paths are trimmed, there is no VCS stamp or build ID, and the Go toolchain is pinned in `go.mod`.

```sh
git clone https://github.com/rowsafe/rowsafe && cd rowsafe
git checkout v1.2.3
make dist VERSION=1.2.3 RELEASE_PUBLIC_KEY=<RELEASE_PUBLIC_KEY>
gh release download v1.2.3 -p SHA256SUMS
(cd dist/1.2.3 && sha256sum --check --ignore-missing ../../SHA256SUMS)
```

Every binary should report `OK`. The `release` workflow runs the same comparison on a fresh machine for every tag and fails the release if a single byte differs.

## Reporting a problem

If any check fails for an official release, don't run the binary, and report it privately through [GitHub security advisories](https://github.com/rowsafe/rowsafe/security/advisories/new).
