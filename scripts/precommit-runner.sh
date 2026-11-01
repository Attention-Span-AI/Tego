# shellcheck shell=bash
# SPDX-License-Identifier: Apache-2.0
#
# precommit-runner.sh — sourced by scripts/precommit.sh (and its test): the step list and the runner that runs a
# phase's steps up to PC_JOBS at a time and reports every step in the order it was added.
#
# pc_add PHASE JOB NAME KIND COMMAND...: adds a step. PHASE is static, tests or integration (any other is refused and
#   counted as a failure: a step of a phase never run would never report). Steps of one PHASE sharing a JOB run one
#   after another in one slot (two golangci-lint runs share a lock, so they share a job); jobs run concurrently. KIND
#   is "step" (a failure fails the run), "report" (its first line is printed after the name, never a failure) or
#   "note" (COMMAND is the text to print; nothing runs). COMMAND's words are kept exactly (a space or a * inside one
#   stays one word).
# pc_run PHASE: runs that phase's jobs, at most PC_JOBS at once, the jobs named in PC_FIRST (space-separated job
#   names, the longest) started first, and prints each step, in the order added, as soon as it and every step before
#   it are done. PC_JOBS=1 runs the phase's steps one after another in the order added.
# pc_stop: stops the running jobs and every process their steps started (an EXIT trap's interrupt).
# pc_finish: prints the verdict line (PC_VERDICT when set, else "precommit: every step passed") and returns 0 when
#   every step passed; 1 when one failed or was never reported.
#
# Each step's output goes to its own file and its exit status and duration to another, written last by a rename:
# a step whose shell is killed leaves no status and is reported as FAIL, never as ok. Needs PC_TMP (a private
# directory) and PC_JOBS (a positive integer).

pc_phase=() pc_job=() pc_name=() pc_kind=() pc_cmd=() pc_failed=() pc_printed=0

pc_add() {
	local phase=$1 job=$2 name=$3 kind=$4 cmd
	shift 4
	case "$phase" in static | tests | integration) ;; *)
		# Refused and counted as failed, so the verdict cannot pass over it.
		echo "precommit-runner: step '$name' has an unknown phase '$phase'" >&2
		pc_failed+=("$name")
		return 2
		;;
	esac
	if [ "$kind" = note ]; then cmd="$*"; else cmd="$(printf '%q ' "$@")"; fi
	pc_phase+=("$phase") pc_job+=("$job") pc_name+=("$name") pc_kind+=("$kind") pc_cmd+=("$cmd")
}

# pc_step I: runs step I with its output in PC_TMP/I.out, then writes "STATUS SECONDS" to PC_TMP/I.rc.
pc_step() {
	local i=$1 start=$SECONDS rc
	# pc_add stored the words quoted (printf %q), so eval gives back exactly the words it was given.
	eval "${pc_cmd[$i]}" >"$PC_TMP/$i.out" 2>&1
	rc=$?
	printf '%s %s\n' "$rc" "$((SECONDS - start))" >"$PC_TMP/$i.rc.new" && mv "$PC_TMP/$i.rc.new" "$PC_TMP/$i.rc"
}

# pc_runjob I...: one job's steps, in order.
pc_runjob() {
	local i
	for i in "$@"; do pc_step "$i"; done
}

pc_report() {
	local i=$1 rc=killed dur='?' name=${pc_name[$1]}
	[ "${#name}" -lt 48 ] || name="$name " # a long name keeps a space before its result
	if [ "${pc_kind[$i]}" = note ]; then
		printf '%-48s%s\n' "$name" "${pc_cmd[$i]}"
		return
	fi
	[ -s "$PC_TMP/$i.rc" ] && read -r rc dur <"$PC_TMP/$i.rc"
	if [ "${pc_kind[$i]}" = report ]; then
		printf '%-48s%s\n' "$name" "$(head -n 1 "$PC_TMP/$i.out" 2>/dev/null)"
		return
	fi
	if [ "$rc" = 0 ]; then
		printf '%-48s%s\n' "$name" "ok (${dur}s)"
		return
	fi
	printf '%-48s%s\n' "$name" "FAIL (${dur}s)"
	[ "$rc" != killed ] || echo "    no exit status: the step was killed before it finished"
	[ ! -e "$PC_TMP/$i.out" ] || sed 's/^/    /' "$PC_TMP/$i.out"
	pc_failed+=("${pc_name[$i]}")
}

# pc_flush: reports the steps that are done, in order, up to the first that is not.
pc_flush() {
	while [ "$pc_printed" -lt "${#pc_name[@]}" ]; do
		local i=$pc_printed
		[ "${pc_kind[$i]}" = note ] || [ -e "$PC_TMP/$i.rc" ] || [ -e "$PC_TMP/$i.gone" ] || return 0
		pc_report "$i"
		pc_printed=$((i + 1))
	done
}

pc_run() {
	local phase=$1 i j k running next=0 first
	local -a queue=() keys=() started=()
	for i in "${!pc_name[@]}"; do
		[ "${pc_phase[$i]}" = "$phase" ] && [ "${pc_kind[$i]}" != note ] || continue
		k=-1
		for j in "${!keys[@]}"; do [ "${keys[$j]}" = "${pc_job[$i]}" ] && k=$j; done
		if [ "$k" -lt 0 ]; then
			keys+=("${pc_job[$i]}") queue+=("$i")
		else
			queue[k]="${queue[$k]} $i"
		fi
	done
	# The jobs PC_FIRST names start first; the print order stays the order added.
	for first in 1 0; do
		for j in "${!keys[@]}"; do
			case " ${PC_FIRST:-} " in *" ${keys[$j]} "*) [ "$first" = 1 ] && started+=("${queue[$j]}") ;; *) [ "$first" = 0 ] && started+=("${queue[$j]}") ;; esac
		done
	done
	queue=("${started[@]}")
	if [ "$PC_JOBS" -le 1 ]; then
		for i in "${!pc_name[@]}"; do
			[ "${pc_phase[$i]}" = "$phase" ] && [ "${pc_kind[$i]}" != note ] || continue
			pc_step "$i"
			pc_flush
		done
	else
		while [ "$next" -lt "${#queue[@]}" ] || [ "$(jobs -rp | wc -l)" -gt 0 ]; do
			running=$(jobs -rp | wc -l)
			while [ "$running" -lt "$PC_JOBS" ] && [ "$next" -lt "${#queue[@]}" ]; do
				# shellcheck disable=SC2086 # a job is a list of step indices
				pc_runjob ${queue[$next]} &
				running=$((running + 1)) next=$((next + 1))
			done
			wait -n 2>/dev/null
			pc_flush
		done
		wait
	fi
	# A step that left no status (its job was killed, or it never started because an earlier step of its job was)
	# is reported as killed.
	for j in "${queue[@]}"; do
		for i in $j; do [ -e "$PC_TMP/$i.rc" ] || : >"$PC_TMP/$i.gone"; done
	done
	pc_flush
}

# pc_tree PID: PID and its descendants, each parent before its children.
pc_tree() {
	local c
	echo "$1"
	for c in $(cat /proc/"$1"/task/*/children 2>/dev/null || ps -o pid= --ppid "$1" 2>/dev/null); do pc_tree "$c"; done
}

# pc_stop: stops every running job and what its step started (go vet, golangci-lint, go test and their children),
# for the caller's EXIT trap: killing a job's shell alone left those running after an interrupt. Each job's shell
# is held (SIGSTOP) while its tree is read, so it starts no next step, then everything gets SIGTERM.
pc_stop() {
	local p
	local -a all=()
	for p in $(jobs -p); do
		kill -STOP "$p" 2>/dev/null
		mapfile -t -O "${#all[@]}" all < <(pc_tree "$p")
	done
	[ "${#all[@]}" -eq 0 ] || kill -TERM "${all[@]}" 2>/dev/null
	for p in $(jobs -p); do kill -CONT "$p" 2>/dev/null; done
}

pc_finish() {
	local i
	# A step never reported (its phase was never run) is a failure, never a pass left out of the count.
	for ((i = pc_printed; i < ${#pc_name[@]}; i++)); do
		if [ "${pc_kind[$i]}" = note ] || [ -e "$PC_TMP/$i.rc" ]; then
			pc_report "$i"
		else
			printf '%-48s%s\n' "${pc_name[$i]} " "FAIL (never ran: phase ${pc_phase[$i]} was not run)"
			pc_failed+=("${pc_name[$i]}")
		fi
	done
	pc_printed=${#pc_name[@]}
	if [ "${#pc_failed[@]}" -gt 0 ]; then
		echo "precommit: failed: ${pc_failed[*]}" >&2
		return 1
	fi
	echo "${PC_VERDICT:-precommit: every step passed}"
}
