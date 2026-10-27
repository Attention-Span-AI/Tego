// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// openURL opens url in the person's browser, the way `serve --open` does: the first of $BROWSER's commands (a
// colon-separated list, each with its own arguments and a %s for the URL, as sensible-browser reads it) and then
// xdg-open that starts. The opener is a detached child: its own session, no standard stream of ours (the null
// device), reaped in the background, so it neither holds the dashboard's terminal nor outlives a Ctrl-C into
// anything but its own browser. It returns an error when no opener started; the caller prints the URL either way
// and never fails the server for it.
//
// tego-control holds no fanotify group, so this start can never meet proc.Arm (sites_test.go).
func openURL(url, browser string) error {
	var cands []string
	for _, c := range strings.Split(browser, ":") {
		if strings.TrimSpace(c) != "" {
			cands = append(cands, c)
		}
	}
	cands = append(cands, "xdg-open")
	err := errors.New("no browser opener found")
	for _, c := range cands {
		argv := strings.Fields(c)
		if strings.Contains(c, "%s") {
			for i, a := range argv {
				argv[i] = strings.ReplaceAll(a, "%s", url)
			}
		} else {
			argv = append(argv, url)
		}
		cmd := proc.Command(argv[0], argv[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if _, serr := proc.Start(cmd); serr != nil {
			err = serr
			continue
		}
		go func() { _ = cmd.Wait() }()
		return nil
	}
	return err
}
