#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# The "proxy" scene, sourced by demo.sh. NOT DONE YET: it prints what it will show.
cmd_proxy() {
  say "Proxy (capture): not built yet in the demo kit"
  echo "It will run an agent with 'capture: forwarder' and 'models:' pointing at a local TLS model stub,"
  echo "so each model call goes through Tego's forwarder and the ledger records ssl_request/ssl_response"
  echo "(method, host, path, model, input/output tokens), then show a call net.http rejects at the proxy."
}
