// SPDX-License-Identifier: Apache-2.0

package web

import "github.com/attention-span-ai/tego/internal/guide"

// tourFrame is teaching context around an existing page. Words and Next are the
// guide's own evidence; navigation never writes a step's state.
type tourFrame struct {
	Words                                 guide.Words
	Next                                  guide.Next
	Steps                                 []tourStop
	Step, Title, Instruction, Fact, State string
	N                                     int
	Pending                               int
	Command, Form                         string
	RecordOpen                            bool
	CanCopy                               bool
	Builder                               bool
	Action, Href, Leave, Page, Move       string
	Waiting                               bool
	Receipt                               *receiptView
}

type tourStop struct {
	guide.StepWords
	Key, Label string
}
