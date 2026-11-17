# nightshift

nightshift is an audit of the agents that run while you sleep. It inventories every unattended agent job on a machine (cron, launchd, systemd timers, GitHub Actions schedules, and Claude scheduled tasks where a stable on-disk store exists) and reports the three things that decide whether it can hurt you: its permission mode, its working directory, and who actually pays for it.

## The problem

Agents that run with nobody watching can fail in ways you only find out about later, and a few of those ways cost real money.

- Claude Code auth precedence puts `ANTHROPIC_API_KEY` above the subscription login. A stray key in a job environment silently switches runs, including cron runs that never ask, from a flat-rate plan to per-token API billing. ([write-up](https://cloudexplainers.com/how-to-fix-claude-code-billing-your-api-key-instead-of-your-plan/))
- Unattended agents misbehave in documented ways. In [Claude Code issue 25963](https://github.com/anthropics/claude-code/issues/25963), a runaway session that restarted killed background processes and resumed its plan after the session was killed. In [issue 69578](https://github.com/anthropics/claude-code/issues/69578), recursive sub-agents burned about 800k tokens and triggered an unexpected 27.60 dollar credits charge.
- Schedulers create jobs, and usage reporters like ccusage report spend after it happens. Nothing inventories the unattended agent jobs that already exist across OS schedulers and scores their permission, billing, and working-dir risk before the fact.

nightshift fills that gap.

## What it checks

A job counts as an agent job when its command invokes `claude`, `codex`, `gemini`, `opencode`, `aider`, `crush`, `goose`, `amp`, or `cursor-agent`. For each one it looks at:

- **Permission mode.** `--dangerously-skip-permissions`, `bypassPermissions`, `--allow-all`, and `-y`/`--yes` are HIGH. `acceptEdits` is LOW. No flag means the default, which prompts.
- **Working directory.** The home directory, the filesystem root, or a prod-looking path is HIGH. A repo directory is LOW. If the directory is unknown, that is noted.
- **Billing.** It reads the job's own environment, names only: `ANTHROPIC_API_KEY` for claude, `OPENAI_API_KEY` for codex, `GEMINI_API_KEY` or `GOOGLE_API_KEY` for gemini. If a key is present, the job bills the API key per token, not the subscription, and that is HIGH.
- **Missing guardrails.** A command with no `--max-turns`, `--max-budget-usd`, or timeout is flagged.
- **Frequency.** A schedule that fires more often than hourly is flagged.

Severity is HIGH if any factor is HIGH, MEDIUM if there is a flag but nothing HIGH, and LOW otherwise. Jobs that are not agent jobs are counted in the summary and not scored.

## Install

Python 3.10 or newer, standard library only. There is no install step, no network access, and no LLM. Clone the repo and run:

```
python3 nightshift.py
```

## Usage

Run `python3 nightshift.py` with no flags to audit the current machine.

Flags:

- `--json` prints machine readable output.
- `--explain` prints the billing precedence rule for each verdict.
- `--cron-file PATH` reads this crontab file.
- `--launchd-dir DIR` scans this directory of plists.
- `--systemd-dir DIR` scans this directory of timer and service units.
- `--workflows-root DIR` looks for `.github/workflows` under this root.

The last four point nightshift at specific sources, which is how the demo and the tests run.

Exit codes: `0` means no HIGH findings, `1` means HIGH findings were found, `2` means a usage error.

## Demo

Run from the repo root:

```
python3 nightshift.py --cron-file fixtures/crontab --launchd-dir fixtures/launchd --systemd-dir fixtures/systemd --workflows-root fixtures/workflows
```

It exits with code 1. Output:

<!-- demo-output-start -->
```text
SOURCE                        SCHEDULE      COMMAND                                             PERM     WORKDIR  BILLING  SEVERITY
-----------------------------------------------------------------------------------------------------------------------------------
cron:fixtures/crontab         */15 * * * *  claude -p --dangerously-skip-permissions run ni...  HIGH     unknown  HIGH     HIGH
launchd:com.example.nightly   every 7200s   codex -p --permission-mode acceptEdits --max-tu...  LOW      LOW      LOW      LOW
systemd:nightly.timer         daily         /usr/bin/gemini -p --max-budget-usd 5 nightly s...  default  HIGH     HIGH     HIGH
workflow:.github/workflow...  30 2 * * *    opencode run nightly review                         default  unknown  LOW      MEDIUM
4 agent jobs: 2 HIGH, 1 MEDIUM, 1 LOW; 1 non-agent jobs counted, not scored.
note: claude: no scheduled-task store found
```
<!-- demo-output-end -->

The cron claude job is HIGH on permission, billing, and frequency. The systemd gemini job is HIGH on billing and on running in root. The codex launchd job is LOW. The opencode workflow is MEDIUM for a missing guardrail. The rsync cron job is counted, not scored. The demo was produced on a machine with no Claude scheduled-task store, so on a machine with one, its jobs appear in the table instead of the note line.

## Guarantees

- **Read-only.** nightshift never executes a scheduled command. Scanning leaves files untouched, and a test covers this.
- **No secrets printed.** Environment variables are tracked by name only. Values are discarded at parse time.

## Tests

```
python3 -m unittest discover -s tests
```

There are 30 tests. They cover all five parsers, billing precedence, the read-only guarantee, exit codes, and a golden test that checks the demo output above against a live run.

Supported on macOS and Linux. Windows is out of scope for v1.
