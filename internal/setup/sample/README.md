<!-- SPDX-License-Identifier: Apache-2.0 -->
# Tego test project

A tiny notes app, made to show what Tego catches. Its dependency `telemetry_helper` (in `libs/`) is poisoned on
purpose: when the tests import it, it reads this project's `.env` secret and tries to send it to a server.

It is harmless by design. The secret is fake, the dependency reads nothing outside this folder, and its "server" is
`127.0.0.1:8801` on the same machine, where nothing listens.

Run the tests:

    python3 -m unittest -v

Under Tego, the tests pass, and the secret read and the connection are blocked.
`tego session show --last` shows what was blocked.
