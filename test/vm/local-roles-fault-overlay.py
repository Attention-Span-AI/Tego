#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build an explicit, disposable guest fault adapter without product hooks.

This writes an overlay only. The caller builds it through the site's resource
wrappers and runs the result only in a guest. The source refuses fault activation
without the guest marker, root and an explicit mode. Keep the emitted source and
overlay beside the binary digest as qualification evidence.
"""

import argparse
import json
from pathlib import Path


HOOK = r'''
// rolesGuestFault exists only in the disposable qualification overlay.
func (w *Writer) rolesGuestFault(e *record.Event) (func(), error) {
	noop := func() {}
	mode := os.Getenv("TEGO_ROLES_GUEST_MODE")
	if mode == "" || mode == "after-packet" || e.Kind != record.KindAnswer {
		return noop, nil
	}
	if os.Geteuid() != 0 || os.Getenv("TEGO_DISPOSABLE_HOST") != "kvm" {
		return noop, errors.New("roles guest adapter requires disposable guest root")
	}
	marker, err := os.Lstat("/run/roles1-guest")
	if err != nil || !marker.Mode().IsRegular() || marker.Mode().Perm() != 0600 {
		return noop, errors.New("roles guest adapter requires /run/roles1-guest mode 0600")
	}
	owner, ok := marker.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 { return noop, errors.New("roles guest marker must be root owned") }
	dir := os.Getenv("TEGO_ROLES_GUEST_DIR")
	if !filepath.IsAbs(dir) {
		return noop, errors.New("roles guest adapter requires an absolute control directory")
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode().Perm() != 0700 {
		return noop, errors.New("roles guest control directory must be mode 0700")
	}
	dirOwner, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok || dirOwner.Uid != 0 { return noop, errors.New("roles guest control directory must be root owned") }
	fileSync, dirSync, out := syncApprovalFile, fsyncDir, w.out
	restore := func() { syncApprovalFile, fsyncDir, w.out = fileSync, dirSync, out }
	switch mode {
	case "before-append":
		return restore, rolesGuestBarrier(dir, mode)
	case "before-fsync":
		syncApprovalFile = func(f *os.File) error {
			if err := rolesGuestBarrier(dir, mode); err != nil { return err }
			return fileSync(f)
		}
	case "file-eio":
		syncApprovalFile = func(*os.File) error { return unix.EIO }
	case "run-dir-eio", "parent-dir-eio", "dir-einval":
		calls := 0
		fsyncDir = func(d *sys.FD) error {
			calls++
			if mode == "dir-einval" { return unix.EINVAL }
			if mode == "run-dir-eio" && calls == 1 || mode == "parent-dir-eio" && calls == 2 { return unix.EIO }
			return dirSync(d)
		}
	case "short-write":
		w.out = rolesGuestShortWriter{w.out}
	case "invalid-actor":
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(e.Payload, &fields); err != nil { return restore, err }
		fields["actor"] = json.RawMessage(`{"uid":21001,"pid":42,"start_boot_ns":10,"user_namespace":4026531837,"source":"kernel-local-uid","role":"owner"}`)
		e.Payload, err = json.Marshal(fields)
		return restore, err
	default:
		return restore, fmt.Errorf("roles guest adapter: unknown mode %q", mode)
	}
	return restore, nil
}

type rolesGuestShortWriter struct { io.Writer }

func (w rolesGuestShortWriter) Write(b []byte) (int, error) {
	if len(b) > 8 { b = b[:8] }
	n, err := w.Writer.Write(b)
	if err != nil { return n, err }
	return n, io.ErrShortWrite
}

func rolesGuestBarrier(dir, phase string) error {
	if err := os.WriteFile(filepath.Join(dir, "entered"), []byte(phase+"\n"), 0600); err != nil { return err }
	deadline := time.Now().Add(60*time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, "resume")); err == nil { return nil } else if !os.IsNotExist(err) { return err }
		time.Sleep(10*time.Millisecond)
	}
	return errors.New("roles guest adapter: barrier timed out")
}
'''


def generate(root: Path, out: Path, negative_sync: bool = False) -> Path:
    root, out = root.resolve(), out.resolve()
    source = root / "internal/ledger/approval.go"
    text = source.read_text()
    imports = '\t"errors"\n'
    if text.count(imports) != 1:
        raise ValueError("approval imports changed; inspect adapter before rebuilding")
    text = text.replace(imports, '\t"encoding/json"\n' + imports + '\t"io"\n\t"path/filepath"\n\t"syscall"\n\t"time"\n')
    target = "\tdefer w.mu.Unlock()\n\tif err := w.appendNext(e); err != nil {"
    if text.count(target) != 1:
        raise ValueError("AppendSync changed; inspect adapter before rebuilding")
    text = text.replace(target, "\tdefer w.mu.Unlock()\n\trestore, faultErr := w.rolesGuestFault(e)\n\tdefer restore()\n\tif faultErr != nil { w.durability = faultErr; return faultErr }\n\tif err := w.appendNext(e); err != nil {")
    if negative_sync:
        target = "\treturn w.syncRequired()\n}"
        if text.count(target) != 2:
            raise ValueError("required sync changed; inspect negative witness")
        text = text.replace(target, "\treturn nil // deliberate qualification mutant: approval skips required sync\n}", 1)
    out.mkdir(parents=True, exist_ok=True)
    overlaid = out / "approval.go"
    overlaid.write_text(text + HOOK)
    overlay = out / "overlay.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(overlaid)}}, indent=2) + "\n")
    return overlay



BROKER_WITNESS = r"""
// rolesGuestPacketBarrier holds the received packet before decision-time facts.
func rolesGuestPacketBarrier(data []byte) {
    if os.Getenv("TEGO_ROLES_GUEST_MODE") != "after-packet" { return }
    cmd, err := decodeCommand(data)
    if err != nil || cmd.Action != "answer" { return }
    if os.Geteuid() != 0 || os.Getenv("TEGO_DISPOSABLE_HOST") != "kvm" { panic("packet barrier requires disposable guest root") }
    marker, err := os.Lstat("/run/roles1-guest")
    if err != nil || !marker.Mode().IsRegular() || marker.Mode().Perm() != 0600 { panic("packet barrier marker") }
    owner, ok := marker.Sys().(*syscall.Stat_t)
    if !ok || owner.Uid != 0 { panic("packet barrier marker owner") }
    dir := os.Getenv("TEGO_ROLES_GUEST_DIR")
    st, err := os.Lstat(dir)
    if err != nil || !filepath.IsAbs(dir) || !st.IsDir() || st.Mode().Perm() != 0700 { panic("packet barrier control directory") }
    owner, ok = st.Sys().(*syscall.Stat_t)
    if !ok || owner.Uid != 0 { panic("packet barrier control owner") }
    if err := os.WriteFile(filepath.Join(dir, "packet-entered"), []byte("after-packet\n"), 0600); err != nil { panic(err) }
    deadline := time.Now().Add(5*time.Second)
    for time.Now().Before(deadline) {
        if _, err := os.Stat(filepath.Join(dir, "packet-resume")); err == nil { return } else if !os.IsNotExist(err) { panic(err) }
        time.Sleep(time.Millisecond)
    }
    panic("packet barrier timed out")
}

// rolesGuestReplyWitness records the actual broker refusal, never session data.
func rolesGuestReplyWitness(c *net.UnixConn, r response, packetPIDFD bool) {
    if os.Getenv("TEGO_ROLES_GUEST_WITNESS") != "1" || r.Code == "" { return }
    if os.Geteuid() != 0 || os.Getenv("TEGO_DISPOSABLE_HOST") != "kvm" { panic("broker witness requires disposable guest root") }
    marker, err := os.Lstat("/run/roles1-guest")
    if err != nil || !marker.Mode().IsRegular() || marker.Mode().Perm() != 0600 { panic("broker witness marker") }
    owner, ok := marker.Sys().(*syscall.Stat_t)
    if !ok || owner.Uid != 0 { panic("broker witness marker owner") }
    dir := os.Getenv("TEGO_ROLES_GUEST_DIR")
    st, err := os.Lstat(dir)
    if err != nil || !filepath.IsAbs(dir) || !st.IsDir() || st.Mode().Perm() != 0700 { panic("broker witness control directory") }
    owner, ok = st.Sys().(*syscall.Stat_t)
    if !ok || owner.Uid != 0 { panic("broker witness control owner") }
    raw, err := c.SyscallConn()
    if err != nil { panic(err) }
    var cred *unix.Ucred
    var credErr error
    if err = raw.Control(func(fd uintptr) { cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || credErr != nil {
        // The broker's own shutdown closes a connection it has not yet taken a command from (server.close), and a refusal
        // written to it reaches no one: no peer received it, so there is nothing to witness. A failure to read the
        // credentials of an open connection is still the witness's own failure.
        if errors.Is(err, net.ErrClosed) { return }
        panic("broker witness peer")
    }
    data, err := json.Marshal(struct {
        PID int32 `json:"peer_pid"`
        UID uint32 `json:"peer_uid"`
        Code string `json:"code"`
        Error string `json:"error"`
        PacketPIDFD bool `json:"packet_pidfd"`
    }{cred.Pid, cred.Uid, r.Code, r.Error, packetPIDFD})
    if err != nil { panic(err) }
    out, err := os.OpenFile(filepath.Join(dir, "broker-replies.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
    if err != nil { panic(err) }
    _, err = out.Write(append(data, '\n'))
    closeErr := out.Close()
    if err != nil || closeErr != nil { panic("broker witness append") }
}
"""


def generate_broker_witness(root: Path, out: Path) -> dict:
    root, out = root.resolve(), out.resolve()
    source = root / "internal/runtime/ask/socket.go"
    text = source.read_text()
    target = "func (s *server) reply(c *net.UnixConn, r response) {\n"
    if text.count(target) != 1 or text.count('\t"os"\n') != 1 or text.count('\t"errors"\n') != 1:
        raise ValueError("broker reply changed; inspect witness before rebuilding")
    extra_imports = "".join('\t"' + name + '"\n' for name in ("path/filepath", "syscall") if '\t"' + name + '"\n' not in text)
    text = text.replace('\t"os"\n', '\t"os"\n' + extra_imports)
    text = text.replace(target, target + "\trolesGuestReplyWitness(c, r, s.packetPIDFD)\n")
    packet_read = "\tnow, nowStarted, err := s.identify(c)\n"
    if text.count(packet_read) != 1:
        raise ValueError("post-packet identity read changed; inspect barrier before rebuilding")
    text = text.replace(packet_read, "\trolesGuestPacketBarrier(buf[:n])\n" + packet_read)
    out.mkdir(parents=True, exist_ok=True)
    overlay_source = out / "socket.go"
    overlay_source.write_text(text + BROKER_WITNESS)
    return {str(source): str(overlay_source)}

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--broker-witness-only", action="store_true", help="record actual broker error replies without injecting a record fault")
    parser.add_argument("--negative-sync", action="store_true", help="deliberately omit answer durability; separate negative witness only")
    args = parser.parse_args()
    if args.broker_witness_only:
        args.out.mkdir(parents=True, exist_ok=True)
        overlay = args.out / "overlay.json"
        replacements = generate_broker_witness(args.root, args.out)
    else:
        overlay = generate(args.root, args.out, args.negative_sync)
        replacements = json.loads(overlay.read_text())["Replace"]
        replacements.update(generate_broker_witness(args.root, args.out))
    overlay.write_text(json.dumps({"Replace": replacements}, indent=2) + "\n")
    print(overlay)


if __name__ == "__main__":
    main()
