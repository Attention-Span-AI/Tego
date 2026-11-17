// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/attention-span-ai/tego/internal/setup"
	uv "github.com/charmbracelet/ultraviolet"
)

// Exercise the actual adapter and every question, independently of later route
// choices. An early answer during a walk is fine; a live field losing its input
// subscription is not. The controlling-PTY routes also exercise the decoder.
func TestGuideQuestionKeyWalks(t *testing.T) {
	seen := map[string]bool{}
	for _, route := range guidePTYRoutes() {
		for _, step := range route.steps {
			if seen[step.prompt] {
				continue
			}
			seen[step.prompt] = true
			t.Run(step.prompt, func(t *testing.T) {
				t.Parallel()
				random := rand.New(rand.NewPCG(48, 2))
				alphabet := []tea.Msg{
					uv.KeyPressEvent{Code: 'a', Text: "a"}, uv.KeyPressEvent{Code: 'n', Text: "n"},
					uv.KeyPressEvent{Code: '/', Text: "/"}, uv.KeyPressEvent{Code: uv.KeyEscape},
					uv.KeyPressEvent{Code: uv.KeyTab}, uv.KeyPressEvent{Code: uv.KeyUp}, uv.KeyPressEvent{Code: uv.KeyDown},
					uv.KeyPressEvent{Code: uv.KeyEnd}, uv.KeyPressEvent{Code: 'n', Mod: uv.ModCtrl},
					uv.KeyPressEvent{Code: ' ', Text: " "}, uv.KeyPressEvent{Code: uv.KeyEnter},
					uv.KeyPressEvent{Code: uv.KeyBackspace}, uv.PasteEvent{Content: "pasted"},
					uv.KeyPressEvent{Code: uv.KeyTab, Mod: uv.ModShift},
				}
				for sequence := range 300 {
					var events []tea.Msg
					if sequence == 0 {
						// Enter finishes filtering in both Select and MultiSelect.
						for _, c := range "/no" {
							events = append(events, uv.KeyPressEvent{Code: c, Text: string(c)})
						}
						events = append(events, uv.KeyPressEvent{Code: uv.KeyEnter})
					} else {
						for range 1 + random.IntN(16) {
							events = append(events, alphabet[random.IntN(len(alphabet))])
						}
					}
					events = append(events, uv.KeyPressEvent{Code: uv.KeyEscape}, uv.KeyPressEvent{Code: uv.KeyEscape})
					kind := "select"
					switch {
					case step.prompt == "Which rules?":
						kind = "multi"
						// Toggle the first item and submit; if that unchecked
						// the sole item, toggle it back and submit again.
						events = append(events, uv.KeyPressEvent{Code: uv.KeyHome}, uv.KeyPressEvent{Code: ' ', Text: " "}, uv.KeyPressEvent{Code: uv.KeyEnter}, uv.KeyPressEvent{Code: ' ', Text: " "})
					case strings.HasPrefix(step.prompt, "Paste "), strings.HasPrefix(step.prompt, "Path "), strings.HasPrefix(step.prompt, "What command"), strings.HasPrefix(step.prompt, "Other hosts"):
						kind = "text"
						events = append(events, uv.KeyPressEvent{Code: 'u', Mod: uv.ModCtrl}, uv.PasteEvent{Content: "valid.example"})
					}
					events = append(events, uv.KeyPressEvent{Code: uv.KeyEnter}, uv.KeyPressEvent{Code: uv.KeyEnter})
					input := &guideEvents{events: make(chan tea.Msg, len(events))}
					for _, event := range events {
						input.events <- event
					}
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					g := newWalk(nil, io.Discard, true)
					g.accessible, g.ctx, g.terminal = false, ctx, &guideTerminal{input: input}
					items := []choice{{name: "no-secrets", checked: true}, {name: "repo-only-writes", checked: true}, {name: "no-prod", checked: true}}
					var err error
					switch kind {
					case "select":
						_, err = g.chooseOne(step.prompt, items)
					case "multi":
						_, err = g.chooseSeveral(step.prompt, items)
					case "text":
						valid := validToken
						if strings.HasPrefix(step.prompt, "Other hosts") {
							valid = func(s string) error { return setup.ValidateHosts(splitList(s)) }
						}
						_, err = g.typeText(step.prompt, "", strings.HasPrefix(step.prompt, "Paste "), valid)
					}
					cancel()
					if err != nil {
						t.Fatalf("seed 48/2 sequence %d (%s): %v", sequence, kind, err)
					}
				}
			})
		}
	}
}
