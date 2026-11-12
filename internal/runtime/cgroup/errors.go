// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"syscall"
)

// Sentinel errors, one per failure class (§9 "Naming"); every one is wrapped with %w around the
// underlying errno where there is one so errors.Is reaches both.
var (
	// ErrCgroupExists is returned by Create when the run scope already exists: run ids are single-use,
	// so this is corruption or reuse, never a race (§4 Create).
	ErrCgroupExists = errors.New("cgroup: run cgroup already exists")
	// ErrNotDelegated is returned by Detect when it cannot show a cgroup v2 subtree this process may
	// use: none is delegated to the invoking uid, the mount is not cgroup2, or — for any uid — the
	// mount has not been shown to hold this process's own cgroup (§6 case 39).
	ErrNotDelegated = errors.New("cgroup: no delegated cgroup v2 subtree")
	// ErrNotCgroup2 is returned when the mount at the root is not cgroup2fs, which for Detect's uid-0
	// branch includes a mount point that cannot be statted at all.
	ErrNotCgroup2 = errors.New("cgroup: not a cgroup v2 filesystem")
	// ErrOutsideSubtree is returned by FS.CanPlace when this process runs outside the subtree Detect
	// found and may not move a process into it (case 41): the subtree is this uid's, but no run can be
	// placed in it from here.
	ErrOutsideSubtree = errors.New("cgroup: this process runs outside its delegated cgroup v2 subtree")
	// ErrBesideSubtree is the one ErrOutsideSubtree refusal that a shell inside the subtree cures: this process's
	// cgroup was read and lies beside the subtree, which Detect found delegated and writable, so the user manager
	// that owns it runs, and only the ancestor the kernel asks about is not this uid's (an SSH or console login's
	// session scope, a service). Callers name the shell to open on it (doctor's Report.OutsideUserManager, the
	// next: line of tego run, watch and test); an unreadable /proc/self/cgroup matches ErrOutsideSubtree alone.
	ErrBesideSubtree = errors.New("cgroup: this process runs beside its delegated cgroup v2 subtree, not in it")
	// ErrNoUserManager is the one ErrNotDelegated refusal whose cure is not delegation: no user manager runs for the
	// uid, so its user@<uid>.service has no cgroup to delegate (an account reached through su or sudo -u that never
	// logged in and has no linger). Its remedy is NoManagerFix; doctor's Report.NoUserManager and tego setup's check
	// name LingerCommand.
	ErrNoUserManager = errors.New("cgroup: no user manager runs for this user")
	// ErrControllerMissing is the class of a *MissingControllerError (case 31).
	ErrControllerMissing = errors.New("cgroup: controller not enabled on the delegated subtree")
	// ErrInvalidLimit is a limit value the kernel refused with EINVAL (§4 SetLimits).
	ErrInvalidLimit = errors.New("cgroup: invalid limit value")
	// ErrBusy is returned by Remove when the scope still holds a task after every retry (case 9);
	// the caller defers the removal to the next sweep pass.
	ErrBusy = errors.New("cgroup: cgroup still busy after retries")
	// ErrBadName is a malformed agent id or run id passed to Create.
	ErrBadName = errors.New("cgroup: bad agent or run name")
)

// DetectError is every refusal Detect and FS.CanPlace return: what could not be shown, the one action
// that cures that, and the sentinels it matches (ErrNotDelegated, ErrNotCgroup2, ErrOutsideSubtree, the
// errno). The remedy is a field rather than prose a caller splits out of Error(), because ErrNotDelegated
// covers causes with different cures — the hierarchy, a cgroup namespace's own mount (case 39),
// Delegate= — and doctor's D3 prints the one this refusal names (docs/p0/limits-check-doctor-cli.md R27
// D3).
type DetectError struct {
	// Diagnosis is what Detect could not show, beginning with the sentinel's own text.
	Diagnosis string
	// Remedy is the one action that cures it.
	Remedy string
	wraps  []error
}

// Error renders "<diagnosis>; fix: <remedy>", the one-line form every other refusal here uses.
func (e *DetectError) Error() string { return e.Diagnosis + "; fix: " + e.Remedy }

// Unwrap exposes the sentinels and the errno for errors.Is.
func (e *DetectError) Unwrap() []error { return e.wraps }

// refuse builds a DetectError whose diagnosis is the formatted text and which matches every error in
// wraps.
func refuse(remedy string, wraps []error, format string, args ...any) *DetectError {
	return &DetectError{Diagnosis: fmt.Sprintf(format, args...), Remedy: remedy, wraps: wraps}
}

// MissingControllerError says which controller a limit needed and how to delegate it. It is the
// ENOENT branch of SetLimits (case 31), kept distinct from a bad value (ErrInvalidLimit) because the
// fix is different: the parent's cgroup.subtree_control, not the contract.
type MissingControllerError struct {
	Controller string // cpu | memory | pids
	Limit      string // the contract key that asked for the write, e.g. limits.cpu
	File       string // the control file that does not exist
	Root       string // the delegated root the controller must be enabled on
	// Privileged is FS.Privileged(): the root is the cgroup2 mount point, not a systemd user
	// delegation. It only selects the wording of Fix(), because the lever differs (see Fix).
	Privileged bool
	// Offered is Root's cgroup.controllers as a set, read when the refusal was built (Offered), nil when it could
	// not be read: only for a controller listed there can the launcher enable it in Root's cgroup.subtree_control
	// itself. It too only selects the wording of Fix().
	Offered map[string]bool
	Errno   syscall.Errno
	// EnableErr is the refusal of the write that should have enabled the controller in a slice above the
	// scope (FS.Create), nil when none was refused: the cause, where the missing file is only the symptom.
	EnableErr error
}

// Error names the controller, the file, the refused enable when there was one, and the one-line fix.
func (e *MissingControllerError) Error() string {
	cause := ""
	if e.EnableErr != nil {
		cause = "; enabling it failed: " + e.EnableErr.Error()
	}
	limit := ""
	if e.Limit != "" {
		limit = ", so " + e.Limit + " cannot be applied and the run is refused"
	}
	return fmt.Sprintf("cgroup: controller %q is not delegated%s (%s: %v%s); fix: %s",
		e.Controller, limit, e.File, e.Errno, cause, e.Fix())
}

// Fix is the one-line delegation fix for the missing controller (case 31 requires the error to name
// it): EnableFix for this error's controller and root.
func (e *MissingControllerError) Fix() string {
	return EnableFix([]string{e.Controller}, e.Root, e.Privileged, e.Offered)
}

// EnableFix is the one-line fix for controllers missing from root's cgroup.subtree_control, shared by a refused
// limit (MissingControllerError) and doctor's D3, so both name the same lever. It depends on which root Detect
// chose, so the parenthetical branches: Delegate= "is available on scope and service units only. It's expressly
// not available on slice units" (systemd.io/CGROUP_DELEGATION), and the cgroup2 mount point is no unit at all, so
// a user@.service.d/ drop-in is not a root launcher's lever. The lever there is the mount root's own
// cgroup.subtree_control. RHEL 9's systemd 252 ships neither cpu in user@.service's Delegate= nor a user slice
// with a CPU weight (GAPS B15); the slice setting below is the one Fedora ships in its user app.slice. Measured
// on fresh AlmaLinux 9.8 guests: with the user@ drop-in alone and a reboot, cpu was in user@UID.service's
// cgroup.controllers but not in its subtree_control; with the drop-in, that slice setting and a reboot, cpu was
// enabled there for a fresh login. Our reading of systemd, not measured: the user manager enables a controller
// there only for a unit of its own that uses it, and memory and pids are on through the default accounting. At
// the mount root, a direct "+cpu" write was gone after a daemon-reload, a transient unit and a service restart
// (read once, after all three); a CPU weight on system.slice and a reboot kept cpu on across the same three
// steps, and limits.cpu applied to a root run.
//
// offered is root's cgroup.controllers (Offered): what root's parent lets it enable, nil when it could not be read.
// A non-root launcher can write "+<controller>" to root's cgroup.subtree_control only for a controller listed
// there; the kernel refuses any other. So when one missing controller is not offered, the fix starts with the
// administrator's steps and says which controllers the user cannot add alone and why. When the file could not be
// read the fix also starts with the administrator's steps, and says it could not tell, rather than claim what the
// kernel offers. *Amended 2026-11-11:* the fix always led with that write, and on AlmaLinux 9.8 a new user's
// user@<uid>.service is offered memory and pids only, so doctor's first lever for cpu was one the user could not
// pull. A root launcher's fix does not read offered: the mount root lists every controller the kernel has.
func EnableFix(missing []string, root string, privileged bool, offered map[string]bool) string {
	plus := make([]string, len(missing))
	for i, c := range missing {
		plus[i] = "+" + c
	}
	add := strings.Join(plus, " ")
	if privileged {
		direct := fmt.Sprintf("echo '%s' > %s/cgroup.subtree_control; Delegate= applies to service and scope "+
			"units, not to the cgroup2 mount root", add, root)
		if slices.Contains(missing, ControllerCPU) {
			direct = "under systemd, which undoes a direct write there: CPUWeight=100 under [Slice] in " +
				"/etc/systemd/system/system.slice.d/, then reboot; without systemd: " + direct
		}
		return fmt.Sprintf("add %q to cgroup.subtree_control of %s (root: %s)", add, root, direct)
	}
	how := "as root: Delegate=cpu memory pids in /etc/systemd/system/user@.service.d/"
	if slices.Contains(missing, ControllerCPU) {
		how += ", and CPUWeight=100 under [Slice] in /etc/systemd/user/app.slice.d/ so the user manager enables cpu"
	}
	if offered == nil {
		return fmt.Sprintf("%s; then reboot (%s/cgroup.controllers could not be read, so whether this user can add "+
			"%q to cgroup.subtree_control of %s alone is not known)", how, root, add, root)
	}
	var absent []string
	for _, c := range missing {
		if !offered[c] {
			absent = append(absent, c)
		}
	}
	if len(absent) > 0 {
		return fmt.Sprintf("%s; then reboot (this user cannot add %q to cgroup.subtree_control of %s alone: "+
			"%s/cgroup.controllers does not offer %s)", how, "+"+strings.Join(absent, " +"), root, root,
			strings.Join(absent, " "))
	}
	return fmt.Sprintf("add %q to cgroup.subtree_control of %s (%s; then reboot)", add, root, how)
}

// Unwrap exposes both the class sentinel and the errno.
func (e *MissingControllerError) Unwrap() []error { return []error{ErrControllerMissing, e.Errno} }
