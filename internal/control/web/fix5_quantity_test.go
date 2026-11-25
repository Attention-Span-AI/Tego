// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"
)

type quantityBranchCase struct{ words, id string }

var layerQuantityBranches []quantityBranchCase

func TestFix5QuantityBranches(t *testing.T) {
	fixtures := append(numberBranchFixtures(t), numberSurfaceFixtures(t)...)
	cases := []quantityBranchCase{
		{"Last 24 hours", "shared.configuration"},
		{"Last 7 days", "shared.configuration"},
		{"Every block, under contract rules or", "shared.policy"},
		{", and every block change", "shared.policy"},
		{"Every line a run records shows here;", "shared.policy"},
		{"The contract no longer compiles here, so its entries are counted from its text; a rule it does not list may be granted without an entry and shows as unknown.", "shared.configuration"},
		{"2 minutes", "shared.configuration"},
		{"4 minutes", "shared.configuration"},
		{"15 minutes", "shared.configuration"},
		{"30 minutes", "shared.configuration"},
		{"1 hour", "shared.configuration"},
		{"1 day", "shared.configuration"},
		{"3 days", "shared.configuration"},
		{"1 week", "shared.configuration"},
		{"45m, 4m, 72h, 3d, 1d12h, 7w", "shared.configuration"},
		{"The kernel holds this run to its fence; inside it, Tego's live layer blocks each fence entry until you lift or grant it", "shared.policy"},
		{"The whole contract: Landlock and Tego's supervisor at every level, plus fanotify and BPF at Plus and Max", "shared.policy"},
		{"The fence: the contract plus every fence entry. Inside the fence, Tego's live layer blocks each entry until you lift or grant it", "shared.policy"},
		{"Yes, fence entries only, each one previewed, confirmed and recorded, optionally for a time. MCP tool switches and model routes are the same exception", "shared.policy"},
		{"With read entries, each read open costs about 0.1 ms more. The plane modes run the full seccomp filter", "shared.policy"},
		{"The mode and the fence's digest at the start; every lift, restore, expiry and refused lift as the launcher applied it; every action under", "shared.policy"},
		{"Nobody for file, program and network rules. MCP tool switches and model routes: the operator, from outside every run, with confirmation", "shared.policy"},
		{"Tego’s live layer enforces this access. A time limit stops new access only. Anything already read or copied, files still open and live connections remain.", "shared.policy"},
		{"Set up: every step is done", "overview.setup-step"},
		{"did not record every file read, so a secret read there may be missing from these counts.", "overview.unrecorded"},
		{"Sorting only · never changes what is refused", "shared.policy"},
		{"in no group.", "logs.keyless"},
		{"(counted once)", "shared.policy"},
		{"Touched within 16 ledger lines and 5 s of a connection outside the contract", "shared.policy"},
		{"System lookups, DNS and the agent's own probes: never next to a secret, never counted as a send", "shared.policy"},
		{"First contact within 16 ledger lines and 5 s of a secret touch", "shared.policy"},
		{"to the contract; each file open then costs about 60 µs more.", "shared.policy"},
		{"First refused within 16 ledger lines and 5 s of a secret touch", "shared.policy"},
		{"Each read the contract refuses gets a line in the record, at Basic protection too. Every file open is slower:", "shared.policy"},
		{"Within 5 seconds of a secret read", "shared.policy"},
		{"exec.ask is reserved and blocks every match", "shared.policy"},
		{"is recorded on each matching line until the run ends", "shared.policy"},
		{"Allow once", "shared.policy"},
		{"Allow once lets this one request through; Deny refuses it.", "shared.policy"},
		{"For this run: the same answer also goes to every later request to", "shared.policy"},
		{"Every run's record, hash-chained and verified", "shared.policy"},
		{"Sending an endpoint elsewhere asks you to check it first; going back to direct applies at once. A request goes with its headers, so a key the agent holds itself goes to the route's backend too.", "shared.policy"},
		{"Which tools of each MCP server an agent may call, decided by Tego's relay on every call. A switch applies to the next call and lasts for this run; the contract is not changed.", "shared.policy"},
		{"A switch lasts for this run. Loosening one (to Allow, or Deny to Ask) asks you to check it first; tightening applies at once. To keep a rule for the next run, change the contract's", "shared.policy"},
		{"The kernel lets this run reach these; Tego's live layer blocks each until you lift it", "shared.policy"},
		{"A time limit stops new access only: anything already read or copied, files still open and live connections stay", "shared.policy"},
		{"Time limits stop new access only", "shared.policy"},
		{"A refused action writes a second line beside it, of kind refused. Each refusal counts once, by its action; the two add up to the run's lines.", "shared.policy"},
		{"not shown here, so the page stays quick; every one is counted above and its lines are in", "run.process-hidden"},
		{"Tego refused it. It was no send next to a secret, so the attempts stopped above do not count it.", "shared.policy"},
		{"route probes to port 65535", "shared.policy"},
		{"Ends the agent and all it started", "shared.policy"},
		{"No resume · record kept", "shared.policy"},
		{"Applies to the next action; the contract file is unchanged. Remove allows again only what the contract allows.", "shared.policy"},
		{"out: a contract made from this run must never allow where its secrets went. Review every other entry before you use it.", "shared.policy"},
		{"Every protection the contract has stays as it is.", "shared.configuration"},
		{"Every protection stays as it is.", "shared.configuration"},
		{"(only what this run did: it drops your deny and ask entries)", "shared.policy"},
		{"proposes from what this run did: only the directories it wrote, the programs it started and the addresses it connected to. It is a proposal: review it before you use it.", "shared.policy"},
		{"The receipt keeps a bounded list of files; Logs has every read.", "run.receipt-more-sensitive"},
		{"Allow once lets this request through. Deny refuses this request.", "shared.policy"},
		{"Agents such as Codex give up after about 30 s", "shared.policy"},
		{"The resume did not take, so the agent stays frozen; Tego keeps trying, and Stop run still ends it (within the stop grace, 10 s by default).", "shared.configuration"},
		{"). Tego itself keeps running. Resume lets it carry on; Stop run still ends it (within the stop grace, 10 s by default).", "shared.configuration"},
		{"). Tego keeps trying, at most 30 s apart, until it takes or you stop the run. Cancel pause makes Tego stop trying; the agent keeps running.", "shared.configuration"},

		{"A watched run has no contract, so Tego cannot tell whether the job needs this destination. Its first contact was within 16 ledger lines and 5 s of a secret touch.", "shared.policy"},
		{"Where each model endpoint's requests go. A change applies to the next request and lasts for this run; only the backends the agent's contract declares can be chosen, and the agent never chooses.", "shared.policy"},
		{"The page never checks this machine itself: the check step is the one", "shared.policy"},
		{"No lift can be confirmed here.", "shared.configuration"},
		{"This run's fence is empty, so nothing can be lifted", "contracts.fence-entries"},
		{"Granted but never used", "run.rule-allowed"},
		{"It records what the agent does and refuses nothing.", "shared.watch-refusals"},
		{"forked, no exec recorded", "event.process-execs-zero"},
		{"No program recorded", "event.process-execs-zero"},
		{"Never answered", "approvals.history"},
		{"No rule can be made from this line:", "event.available-actions-zero"},
		{"The change history missed this one, so the page offers no Undo; the old file holds the text from before.", "shared.configuration"},
		{"There is no network deny list: blocking removes the net.allow entry, so the connection is refused by default", "shared.policy"},
		{"Hash chain checked line by line, but with no anchor: the run did not end, so lines cut from its end would not show", "shared.record-fields"},
		{"The lift has no end on this run; Change rules then opens, to keep it from the next run (its own preview and confirm).", "shared.configuration"},
		{"This change sends nothing anywhere new; go back and apply it from the page.", "editor.changes-zero"},
		{"The same, plus: it can dodge an exec fence entry not yet granted by copying the program to a place where it can write and run. Net and read fence entries cannot be raced. It can never lift its own rules", "shared.policy"},
		{"Notified calls fail and the run ends. Every open, connect and exec is notified, so none reaches a fence entry in between. Descriptors already open work until the run is killed", "shared.policy"},
		{"The operator, from outside every run, with confirmation; never the agent. A same-user process outside every run that reads the run's key can too", "shared.policy"},
		{"The file's rules differ from what this run ran, and nothing dates the change: a profile it extends changed, or this run started from another version of the file · not live on this run", "shared.record-fields"},
		{"The file's rules differ from what this run ran, and nothing dates the change: a profile it extends changed, or this run started from another version of the file · tables show what this run enforces", "shared.record-fields"},
		{"never answered (the run was lost)", "run.request-answers"},
		{", and no limits are suggested until it ends.", "shared.policy"},
		{"The agent is frozen where it stood and does nothing until you resume it (line #", "shared.policy"},
		{"Ask is off: this run's contract has no", "shared.configuration"},
		{"started no program the retained record shows", "run.process-unrecorded"},
		{"on none.", "run.process-no-pid"},
		{", forked, no exec recorded", "event.process-execs-zero"},
		{"Only routine actions refused", "detections.noticed"},
		{"Watched only: all recorded attempts went through", "shared.watch-refusals"},
		{"No rules file to check against", "run.contract-copy"},
		{"Never answered (run lost)", "run.request-answers"},
		{"This run has no approvals (no ask: section)", "shared.configuration"},
		{"(nothing)", "editor.entries-zero"},
		{"No run_end line: the run was lost", "shared.record-fields"},
		{"this run was granted but never used.", "run.proposal-entries"},
		{"Remove: granted but never used", "run.proposal-entries"},
		{"granted but never used", "run.unused"},
		{"Not known: this run did not record every read, so a sensitive file may have been read.", "run.receipt-sensitive-files"},
		{"Complete: every field above was read off a ledger that records it.", "run.receipt-coverage"},
	}
	var markers []marker
	for _, f := range fixtures {
		markers = append(markers, markersIn(t, f.body)...)
	}
	for _, tc := range append(cases, layerQuantityBranches...) {
		t.Run(tc.words, func(t *testing.T) {
			found := false
			for _, m := range markers {
				if m.id == tc.id && strings.Contains(m.words, tc.words) {
					found = true
				}
			}
			if !found {
				t.Fatalf("rendered branch lacks quantity source %s for %q", tc.id, tc.words)
			}
		})
	}
}
