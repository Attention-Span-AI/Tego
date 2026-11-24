# Reviewed Sigstore trust bytes

These files are public Sigstore trust and service configuration, pinned by
SHA-256 in `../scripts/trust.sh`. They are never loaded from run evidence or the
agent's HOME. Cosign v3.1.3 is downloaded by its architecture's reviewed binary
SHA-256 before execution. Updating any pin requires source review and the
bootstrap, release-verification and offline fixture checks again.

Source: [sigstore/root-signing commit
7eecab8a6dc16f2628d935039de829fdf90e21df](https://github.com/sigstore/root-signing/tree/7eecab8a6dc16f2628d935039de829fdf90e21df),
read 2026-11-12. `root.json` comes from `metadata/root.json`;
`trusted_root.json` and `signing_config.v0.2.json` come from `targets/`.
The bootstrap root version is 16 and expires 2027-04-22T19:27:31Z.
These are independently pinned public-service trust files, not credentials.

| File | SHA-256 |
|---|---|
| `root.json` | `27aea7e372aa7864065174f0661784fcf8b0e28b1dbfebeada31a0f1fb19167f` |
| `trusted_root.json` | `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66` |
| `signing_config.v0.2.json` | `9711a6d5375706957a4859af31c5866a4474f81f0544f9f4b76c9c4f4c8a539c` |

Cosign digest source: the official [v3.1.3 release
checksums](https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign_checksums.txt).
Linux amd64 is `4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71`;
Linux arm64 is `c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a`.
The amd64 binary digest was measured against downloaded bytes; the arm64 digest
was read from these official release checksums. Arm64 execution remains owed on
an arm64 GitHub runner.

`setup_trust` refuses an existing state directory, creates private HOME/TUF_ROOT,
then runs `cosign initialize` against only
`https://tuf-repo-cdn.sigstore.dev` with the bootstrap and its hash. Cosign's TUF
client checks threshold signatures, metadata expiry and target hashes. The
script also requires the resulting root, trusted-root target and service
configuration target to retain these reviewed hashes. Valid upstream rotation
therefore stops this version until pins are reviewed. Timestamp/snapshot/targets
metadata may refresh through normal TUF validation. Each cosign operation checks
these retained pins before and after execution. Signing passes the service
configuration and trusted root explicitly.

The isolated process environment contains only PATH, HOME and TUF_ROOT. An
explicitly supplied, consent-checked signing token adds SIGSTORE_ID_TOKEN.
Inherited proxies, XDG paths, Sigstore tokens and GitHub token-request authority
are omitted. The token never appears in cosign's argv. HOME/TUF state and tokens
must never enter the published artifact.

On 2026-11-12, the real pinned amd64 binary initialized this mirror successfully;
the three retained hashes matched. It also verified the published Tego v0.1.2
checksums bundle against issuer `https://token.actions.githubusercontent.com`,
SAN `https://github.com/Attention-Span-AI/Tego/.github/workflows/release.yml@refs/tags/v0.1.2`,
repository `Attention-Span-AI/Tego`, trigger `push`, ref `refs/tags/v0.1.2` and
source commit `8a879b4e6a8833c2fe27bbbf650dce4cdf8fc469`: `Verified OK`.
No Tego executable was run. This checks existing release authentication, not a
new receipt signing run or the still-owed GitHub acceptance rows.
