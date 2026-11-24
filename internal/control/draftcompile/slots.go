// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// errBusy is the refusal of a compilation that found both compiler slots taken for its whole admission wait.
var errBusy = errors.New("busy, try again")

type poolKey struct{}

type governedKey struct{}

// compilerReserve is how many compiler slots beyond the shared ones only a request not marked governed may take
// (WithGoverned): governed programs' compilations share the compiler slots that always existed (cap(slots)) and can
// never take the one kept for a person's own check, so a burst of them cannot make the person's check wait out its
// admission and answer busy. The compilers that can run at once are at most the shared ones and this one.
const compilerReserve = 1

// WithGoverned marks ctx's compilations as made for a governed program's request: they never take the reserved slot.
func WithGoverned(ctx context.Context) context.Context {
	return context.WithValue(ctx, governedKey{}, true)
}

// slotNames are the kernel names a compilation tries, in order: a governed one only the shared names; any other the
// reserved name first and then the shared ones, so it leaves them to governed compilations while it can.
func slotNames(ctx context.Context) []int {
	shared := cap(slots)
	var names []int
	if governed, _ := ctx.Value(governedKey{}).(bool); !governed {
		for name := shared; name < shared+compilerReserve; name++ {
			names = append(names, name)
		}
	}
	for name := range shared {
		names = append(names, name)
	}
	return names
}

// WithPool shares the dashboard's compiler limit across its short-lived path
// helpers. The identifier comes only from the serving process, never a form.
func WithPool(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, poolKey{}, id)
}

// Abstract socket leases survive parent exit when inherited by a compiler on
// stderr. They carry no data and create no filesystem entry. A stalled child
// retains its slot until actual exit, even after the path helper is abandoned.
func compilerLease(ctx context.Context, deadline time.Time) (*os.File, error) {
	id, _ := ctx.Value(poolKey{}).(string)
	if id == "" {
		id = fmt.Sprint(os.Getpid())
	}
	sum := sha256.Sum256([]byte(id))
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, slot := range slotNames(ctx) {
			name := fmt.Sprintf("@tego.draft.v1.%d.%x.%d", os.Geteuid(), sum[:12], slot)
			socket, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
			if errors.Is(err, syscall.EADDRINUSE) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("reserve draft compiler: %w", err)
			}
			lease, err := socket.File()
			_ = socket.Close()
			if err != nil {
				return nil, err
			}
			return lease, nil
		}
		wait := time.Until(deadline)
		if wait <= 0 {
			return nil, errBusy
		}
		if wait > 5*time.Millisecond {
			wait = 5 * time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}
