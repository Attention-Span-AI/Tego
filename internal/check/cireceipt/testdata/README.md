# Public bundle shape fixture

`public-release-v0.1.2.sigstore.json` is the public Tego v0.1.2 release checksums
bundle downloaded on 2026-11-12 from:

https://github.com/Attention-Span-AI/Tego/releases/download/v0.1.2/tego_0.1.2_checksums.txt.sigstore.json

The unit test measures its bundle and certificate shape. It does not establish
trust in a reusable CI signer or use bundle values as independent expectations.
The release workflow differs from the CI receipt workflow. A real CI run remains
owed on GitHub. The matching checksums blob and independently pinned cosign
verification are retained in the task's scratch trust directory.

Bundle SHA-256: `0759fc1223732b8282bb120b719a81e8f1e15bed64a3171d06061d0534341378`.
