# Release checklist

This is the short, repeatable gate for promoting the current alpha to a
stable AgentReins release.  It complements [RELEASING.md](RELEASING.md), which
contains the credentials and implementation details.  A checked item must have
observable evidence (a CI run, a downloaded artifact, or a recorded manual
test); do not check an item from intent alone.

## 1. Candidate and source

- [ ] `main` is clean and the macOS, portable, and packaging CI workflows are
      green for the candidate commit.
- [ ] `CHANGELOG.md` starts with a heading matching the exact tag version,
      e.g. `## [0.3.0] - YYYY-MM-DD`.
- [ ] `python portable/release_contract.py --tag vX.Y.Z --changelog CHANGELOG.md`
      passes.  Prerelease tags (`-alpha`, `-beta`, `-rc`) are only for a
      candidate; a stable tag has no suffix.
- [ ] `python -m unittest discover -s Tests/Portable -p 'test_*.py' -q` passes
      locally (including the release-contract tests).
- [ ] Release notes list known platform limitations and do not describe
      inferred evidence as confirmed behavior.

## 2. Distribution credentials and provenance

- [ ] Apple Developer ID Application certificate, notarization credentials,
      and the protected GitHub release environment are configured.
- [ ] Windows Authenticode PFX and password are configured together (or the
      stable release is explicitly held back).  The workflow verifies every
      executable and installer before checksums are generated.
- [ ] No certificate, password, API key, or local evidence database is staged
      in the commit.
- [ ] The release workflow reports signing/notarization status in its log; a
      SHA-256 sidecar is treated as an integrity check, not a publisher
      signature.

## 3. Artifact matrix

After the tag workflow completes, the GitHub Release must contain all of the
following assets and matching `.sha256` sidecars:

| Platform | Required artifacts | Clean-install checks |
| --- | --- | --- |
| macOS | Universal 2 ZIP (`arm64` + `x86_64`) | signature, notarization/staple, launch on Intel and Apple Silicon |
| Windows | portable EXE, Inno Setup installer, Native Host, ETW helper | install, launch, browser Native Messaging registration, uninstall |
| Linux | x86_64 AppImage, `.deb`, Native Host | launch, per-user service, browser host registration, uninstall |

- [ ] Download every artifact while signed out of GitHub and verify its sidecar
      (`sha256sum -c` or `Get-FileHash`).
- [ ] Test one clean Windows VM and one clean Linux VM/container/desktop.  The
      test records the OS version, architecture, artifact checksum, install
      command, and result.
- [ ] Confirm the first-run experience is usable without developer tooling;
      ETW remains opt-in and Linux collector degradation/permission errors are
      visible in collector health.

## 4. Publish and monitor

- [ ] Create an annotated tag only after sections 1–3 are complete:

  ```bash
  git tag -a vX.Y.Z -m "AgentReins X.Y.Z"
  git push origin vX.Y.Z
  ```

- [ ] Confirm the GitHub Release is **not** marked prerelease and that all
      platform jobs attached assets to the same tag.
- [ ] Smoke-test update checking against the stable release.  It must select
      the stable tag, require a matching digest/sidecar, and never silently
      install or restart the application.
- [ ] Keep the previous stable release available for rollback.  If an artifact
      is defective, mark the release as withdrawn and publish a corrected patch
      version rather than replacing an already downloaded binary.

## 5. Post-release record

Record the tag, commit SHA, CI run URL, artifact checksums, signing/notary
status, clean-environment results, known issues, and rollback decision in the
release issue.  This record is the evidence for the next release review.
