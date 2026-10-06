// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"flag"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseConfigDefaultsAreADR0021sListener(t *testing.T) {
	t.Parallel()
	got, err := parseConfig(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	want := config{
		mode:     modeAllowTouch,
		marks:    []string{"/"},
		workers:  4,
		touch:    []string{"/etc/os-release"},
		stat:     []string{"/usr/bin"},
		delay:    2 * time.Millisecond,
		deadline: 10 * time.Second,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("defaults = %+v, want %+v", got, want)
	}
}

func TestParseConfigTakesEveryFlag(t *testing.T) {
	t.Parallel()
	got, err := parseConfig([]string{
		"-mode", "allow-touch", "-mark", "/", "-mark", "/var/lib/x/", "-workers", "8",
		"-touch", "/etc/hostname", "-touch", "/etc/passwd", "-stat", "/usr", "-stat", "/lib/",
		"-decide-delay", "5ms", "-deadline", "3s",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	want := config{
		mode:     modeAllowTouch,
		marks:    []string{"/", "/var/lib/x"},
		workers:  8,
		touch:    []string{"/etc/hostname", "/etc/passwd"},
		stat:     []string{"/usr", "/lib"},
		delay:    5 * time.Millisecond,
		deadline: 3 * time.Second,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("config = %+v, want %+v", got, want)
	}
}

func TestParseConfigDenyMarksTheMountOfThePathsDirectory(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		args  []string
		path  string
		marks []string
	}{
		{[]string{"-mode", "deny", "-path", "/srv/x/secret"}, "/srv/x/secret", []string{"/srv/x"}},
		{[]string{"-mode", "deny", "-path", "/secret"}, "/secret", []string{"/"}},
		{[]string{"-mode", "deny", "-path", "/srv//x/../x/secret"}, "/srv/x/secret", []string{"/srv/x"}},
		{[]string{"-mode", "deny", "-path", "/srv/x/secret", "-mark", "/srv"}, "/srv/x/secret", []string{"/srv"}},
	} {
		got, err := parseConfig(c.args, &bytes.Buffer{})
		if err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		if got.mode != modeDeny || got.path != c.path || !reflect.DeepEqual(got.marks, c.marks) {
			t.Errorf("%v: mode %q path %q marks %q; want deny, %q, %q", c.args, got.mode, got.path, got.marks, c.path, c.marks)
		}
		if got.workers != 0 || len(got.touch) != 0 || len(got.stat) != 0 {
			t.Errorf("%v: deny mode kept allow-touch's workers/touch/stat: %+v", c.args, got)
		}
	}
}

func TestParseConfigRefusesWhatItCannotRun(t *testing.T) {
	t.Parallel()
	cases := []struct {
		args []string
		msg  string
	}{
		{[]string{"-mode", "bogus"}, "mode"},
		{[]string{"-mode", "deny"}, "-path"},
		{[]string{"-mode", "deny", "-path", "rel/file"}, "absolute"},
		{[]string{"-path", "/x"}, "deny"},
		{[]string{"-mode", "deny", "-path", "/x", "-workers", "2"}, "allow-touch"},
		{[]string{"-mode", "deny", "-path", "/x", "-touch", "/y"}, "allow-touch"},
		{[]string{"-mode", "deny", "-path", "/x", "-stat", "/y"}, "allow-touch"},
		{[]string{"-mode", "deny", "-path", "/x", "-decide-delay", "1ms"}, "allow-touch"},
		{[]string{"-mode", "deny", "-path", "/x", "-deadline", "1s"}, "allow-touch"},
		{[]string{"-workers", "0"}, "workers"},
		{[]string{"-workers", "-3"}, "workers"},
		{[]string{"-deadline", "0"}, "deadline"},
		{[]string{"-deadline", "-1s"}, "deadline"},
		{[]string{"-decide-delay", "-1ms"}, "decide-delay"},
		{[]string{"-mark", ""}, "mark"},
		{[]string{"-mark", "rel"}, "mark"},
		{[]string{"-touch", "rel"}, "absolute"},
		{[]string{"-stat", "rel"}, "absolute"},
		{[]string{"-nope"}, "not defined"},
		{[]string{"stray"}, "unexpected argument"},
	}
	for _, c := range cases {
		var out bytes.Buffer
		_, err := parseConfig(c.args, &out)
		if err == nil {
			t.Errorf("%v: accepted", c.args)
			continue
		}
		if !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%v: error %q lacks %q", c.args, err, c.msg)
		}
		if errors.Is(err, flag.ErrHelp) {
			t.Errorf("%v: reported as a request for help", c.args)
		}
	}
}

func TestParseConfigHelpPrintsTheFlags(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	_, err := parseConfig([]string{"-h"}, &out)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("-h returned %v, want flag.ErrHelp", err)
	}
	for _, want := range []string{"-mode", "-path", "-mark", "-workers", "-touch", "-stat", "-decide-delay", "-deadline", "allow-touch", "deny"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("usage lacks %q:\n%s", want, out.String())
		}
	}
}
