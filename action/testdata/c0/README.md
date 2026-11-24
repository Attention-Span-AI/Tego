# C0: owed certificate measurements

No lab repository exists yet and none of these files has run on GitHub. These are exact lab files, not product
signing. The lab signs only a fixed public blob. Do not copy these permissions into the receipt agent job.
Every run that signs writes the lab repository's name, owner and run to the public Rekor transparency log.
That public record is permanent, including after the lab repository or workflow is deleted.

1. Create a private lab and a public twin. Create no secrets. In the public twin set the repository variable
   `C0_COSIGN_SHA256_AMD64` to an independently checked SHA-256 of cosign v3.1.3 for Linux amd64.
2. Copy `c0.yml` and `c0-reusable.yml` unchanged to `.github/workflows/`. Copy executable `c0-capture.sh` to
   `.github/scripts/c0-capture.sh`. Keep a local copy of these exact files and their SHA-256s.
3. Commit on a `c0/**` branch in the public twin and push it. The push run signs a fixed blob in both a direct job and
   a reusable job. Record the run URL, source and workflow commits. Download both run/attempt/leg artifacts.
4. Dispatch C0 manually on that same branch. Open a same-repository PR from it and retain that PR run's artifacts.
   Rerun all jobs once so the invocation has attempt 2. Retain both attempts separately. A second-account fork
   may exercise the refusal path; it must not sign. No privileged trigger is configured.
5. For every push, dispatch, PR and attempt 2, compare `expected.json`, authenticated `attempt.json`/`jobs.json`,
   `certificate.txt` and the complete `certificate-asn1.txt`. Save the blob, bundle, leaf DER and check output.
   Refresh attempt/jobs metadata after completion, since the in-job copy precedes completion.
6. Write the actual SAN and all Fulcio OIDs, including issuer `.8`, signer URI/digest `.9/.10`, runner `.11`,
   source URI/digest/ref `.12/.13/.14`, repository/owner IDs `.15/.17`, caller config URI/digest `.18/.19`, trigger
   `.20`, invocation/attempt `.21` and visibility `.22`. Record legacy extensions too. Compare signing and Rekor
   times with the exact attempt window. Missing or unexpected deployed extensions block acceptance; retain them.
7. Check that the reusable signer and caller digests remain distinct, that PR source merge SHA and head SHA are
   distinguished, and that attempt 2 names attempt 2. Add exact run/attempt links and observed values to the
   acceptance record. A green job or successful verify-blob alone does not satisfy C0.

Only after these measurements may the signing implementation rely on deployed certificate mappings. B1-3 must
still implement strict comparison and trust bootstrapping, and the full hosted acceptance set remains owed.
No GitHub repository, workflow run, API write or signing operation was performed while preparing this fixture.
