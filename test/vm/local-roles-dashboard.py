#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Guest-only real-credential dashboard POST witness; never prints session secrets."""
import argparse
import hashlib
import html
import http.cookiejar
import json
from pathlib import Path
import re
import time
import sys
import urllib.parse
import urllib.request



def refused_operation(page, name, witness):
    target = html.escape(witness["target"], quote=True)
    if name == "timeline":
        seq = witness["operation_seq"]
        match = re.search(r'<div class="tl v-refused[^"\n]*" id="l' + str(seq) + r'"[^>]*>(.*?)</div>', page, re.S)
        if match is None or target not in match[1]:
            raise AssertionError("timeline lacks held operation's exact refused line")
    elif name == "receipt":
        section = re.search(r'<h3>Refused actions.*?<ul[^>]*>(.*?)</ul>', page, re.S)
        if section is None:
            raise AssertionError("receipt lacks refused actions list")
        rows = re.findall(r'<li>(.*?)</li>', section[1], re.S)
        if not any('title="' + target + '"' in row and re.search(r'<span class="op"[^>]*>open</span>', row) for row in rows):
            raise AssertionError("receipt lacks held operation's own refused open")


def self_check():
    witness = dict(target="/held/one", operation_seq=3)
    good_timeline = '<div class="tl v-refused" id="l3"><span title="/held/one">open</span></div>'
    good_receipt = '<h3>Refused actions</h3><ul><li><span class="op">open</span><span title="/held/one"></span></li></ul>'
    refused_operation(good_timeline, "timeline", witness)
    refused_operation(good_receipt, "receipt", witness)
    # the receipt page's operation word carries attributes (the number inventory's data-number-exclude)
    refused_operation(good_receipt.replace('<span class="op">', '<span class="op" data-number-exclude="receipt.operation">'), "receipt", witness)
    cases = [("timeline-wrong-operation", good_timeline.replace('l3', 'l4'), "timeline"),
             ("timeline-wrong-target", good_timeline.replace('/held/one', '/other'), "timeline"),
             ("timeline-wrong-verdict", good_timeline.replace('v-refused', 'v-allowed'), "timeline"),
             ("receipt-unrelated-refused", good_receipt.replace('/held/one', '/other') + 'Refused approval recorded', "receipt"),
             ("receipt-wrong-op", good_receipt.replace('>open<', '>read<'), "receipt"),
             ("receipt-no-effect-list", 'Refused approval recorded /held/one', "receipt")]
    for name, page, kind in cases:
        try:
            refused_operation(page, kind, witness)
        except AssertionError:
            print(name + "\tFAIL (expected)")
        else:
            raise AssertionError("self-check accepted wrong dashboard outcome: " + name)
    print("DASHBOARD-SELF-CHECK-DONE: " + str(len(cases)) + " wrong outcomes rejected")

def main():
    if sys.argv[1:] == ["--self-check"]:
        self_check()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("run")
    parser.add_argument("ask")
    parser.add_argument("--ended", action="store_true")
    parser.add_argument("--operation-witness", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    source, run, ask = args.source, args.run, args.ask
    deadline = time.monotonic() + 10
    token_url = None
    while time.monotonic() < deadline:
        match = re.search(r"Tego dashboard: (http://127\.0\.0\.1:8484/\?t=[^\s]+)", Path(source).read_text())
        if match:
            token_url = match[1]
            break
        time.sleep(.05)
    if token_url is None:
        raise RuntimeError("dashboard did not print a sign-in URL")
    base = "http://127.0.0.1:8484"
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    with opener.open(token_url, timeout=5) as response:
        response.read()
    if args.ended:
        witnesses = []
        for name, route in (("timeline", "/runs/" + run), ("receipt", "/runs/" + run + "/receipt"), ("history", "/approvals?tab=history")):
            with opener.open(base + route, timeout=5) as response:
                page = response.read().decode()
                status = response.status
            text = html.unescape(re.sub(r"<[^>]+>", " ", page))
            for words in ("approval recorded", "role Owner"):
                if words.casefold() not in text.casefold():
                    raise RuntimeError(name + " lacks authenticated selection: " + words)
            if ">Allowed once</" in page or 'class="b b-allowed">approval recorded' in page.lower():
                raise RuntimeError(name + " presents selection as delivered approval")
            if args.operation_witness and name in ("receipt", "timeline"):
                refused_operation(page, name, json.loads(args.operation_witness.read_text()))
            # Normal pages may contain form CSRF. Preserve page evidence without session secrets.
            clean = re.sub(r'(name="csrf" value=")[^"]+', r'\1REDACTED', page)
            if args.output_dir:
                args.output_dir.mkdir(parents=True, exist_ok=True)
                (args.output_dir / (name + ".html")).write_text(clean)
            witnesses.append(dict(page=name, http_status=status, selection="approval recorded", identity="role Owner", refused_operation=json.loads(args.operation_witness.read_text()) if args.operation_witness else None, sha256=hashlib.sha256(clean.encode()).hexdigest()))
        print(json.dumps(witnesses, indent=2))
        return
    with opener.open(base + "/runs/" + run + "/stop", timeout=5) as response:
        page = response.read().decode()
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', page)
    if csrf is None:
        raise RuntimeError("signed-in stop form did not supply normal CSRF")
    witnesses = []
    for decision in ("approve", "deny"):
        data = urllib.parse.urlencode(dict(csrf=csrf[1], run=run, ask=ask, decision=decision)).encode()
        request = urllib.request.Request(base + "/approvals/answer", data=data, headers={
            "Content-Type": "application/x-www-form-urlencoded", "Origin": base, "Referer": base + "/approvals"})
        with opener.open(request, timeout=5) as response:
            page = response.read().decode()
            status = response.status
        for words in ("only root may answer once", "request remains pending"):
            if words not in page:
                raise RuntimeError("dashboard POST did not show broker refusal: " + decision)
        witnesses.append(dict(decision=decision, final_http_status=status, broker_refusal="only root may answer once", pending=True))
    print(json.dumps(witnesses, indent=2))


if __name__ == "__main__":
    main()
