#!/usr/bin/env python3
"""nightshift: an audit of the agents that run while you sleep.

nightshift inventories every unattended agent job on a machine and reports the
three things that decide whether it can hurt you: its permission mode, its
working directory, and who actually pays for it.

Sources it reads (all read-only file reads, never executing a job command):

  1. cron: the user crontab, or spool files under /var/spool/cron/crontabs,
     /etc/crontab and /etc/cron.d. Environment assignments on lines before a
     job belong to that job.
  2. launchd: property list files under the LaunchAgents and LaunchDaemons
     directories, both per user and system wide.
  3. systemd: user and system timer units plus their matching service units.
  4. GitHub Actions: workflows with an on.schedule trigger under a given root.
  5. Claude scheduled tasks: known on-disk locations only. If no stable store
     exists the tool says so instead of guessing.

For each job that invokes a known agent CLI the tool scores permission mode,
working directory, billing path (which API key names are present in the job's
own environment, by name only), missing guardrails, and schedule frequency.

Secrets are never printed. Environment variables are tracked by NAME only;
values are discarded at parse time and never stored anywhere.

Stdlib only. Python 3.10 or newer. No LLM, no network.
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Job:
    """One scheduled job found in some scheduler.

    env maps variable NAME to True. Values are never stored; a parser must
    drop the value the moment it splits a NAME=value line.
    """

    source: str
    schedule: Optional[str]
    command: Optional[str]
    env: dict = field(default_factory=dict)
    working_dir: Optional[str] = None
    raw_text: str = ""


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nightshift",
        description=(
            "Inventory unattended agent jobs (cron, launchd, systemd, GitHub "
            "Actions) and score their permission mode, working directory and "
            "billing path. Read-only. Never runs a job. Never prints a secret."
        ),
    )
    parser.add_argument(
        "--cron-file",
        metavar="PATH",
        help="read this crontab file instead of discovering crontabs",
    )
    parser.add_argument(
        "--launchd-dir",
        metavar="DIR",
        help="scan this directory of .plist files instead of the default launchd dirs",
    )
    parser.add_argument(
        "--systemd-dir",
        metavar="DIR",
        help="scan this directory of .timer and .service units instead of the defaults",
    )
    parser.add_argument(
        "--workflows-root",
        metavar="DIR",
        help="root under which to look for .github/workflows (default: current directory)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine readable JSON instead of the human table",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="print the precedence rule applied for each billing verdict",
    )
    return parser


# ---------------------------------------------------------------------------
# cron
# ---------------------------------------------------------------------------

# NAME=value where NAME is a shell style identifier. Values may be quoted.
_CRON_ENV_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")

# Special schedule words cron accepts in place of the five fields.
_CRON_SPECIALS = (
    "@reboot",
    "@yearly",
    "@annually",
    "@monthly",
    "@weekly",
    "@daily",
    "@midnight",
    "@hourly",
)


def parse_crontab_text(text: str, source_label: str) -> list[Job]:
    """Parse crontab text into Job objects.

    Environment assignment lines (NAME=value) apply to every job that follows
    them in the file, which is how cron itself treats them. Only the NAME is
    kept. Comments and blank lines are skipped. A job line is a five-field
    schedule (or an @special word) followed by the command.
    """
    jobs: list[Job] = []
    pending_env: dict = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        env_match = _CRON_ENV_RE.match(line)
        if env_match and not line.startswith("@"):
            # Record the name only. The value is discarded here and never kept.
            pending_env[env_match.group(1)] = True
            continue

        schedule: Optional[str]
        command: Optional[str]
        if line.startswith("@"):
            parts = line.split(None, 1)
            if parts[0] not in _CRON_SPECIALS:
                continue
            schedule = parts[0]
            command = parts[1].strip() if len(parts) > 1 else None
        else:
            parts = line.split(None, 5)
            if len(parts) < 6:
                # Not a complete five-field schedule plus command. Skip it
                # rather than guess what was intended.
                continue
            schedule = " ".join(parts[:5])
            command = parts[5].strip() or None

        jobs.append(
            Job(
                source=source_label,
                schedule=schedule,
                command=command,
                env=dict(pending_env),
                working_dir=None,
                raw_text=raw_line,
            )
        )

    return jobs


# ---------------------------------------------------------------------------
# launchd
# ---------------------------------------------------------------------------


def _format_calendar_interval(interval) -> Optional[str]:
    """Render a StartCalendarInterval dict (or list of dicts) as text."""
    if isinstance(interval, list):
        rendered = [_format_calendar_interval(item) for item in interval]
        rendered = [item for item in rendered if item]
        return "; ".join(rendered) if rendered else None
    if not isinstance(interval, dict):
        return None
    order = ("Minute", "Hour", "Day", "Weekday", "Month")
    parts = [f"{key}={interval[key]}" for key in order if key in interval]
    return "calendar " + " ".join(parts) if parts else None


def parse_launchd_plist(path) -> Optional[Job]:
    """Parse one launchd plist into a Job, or None if it is unreadable.

    Reads ProgramArguments, StartCalendarInterval, StartInterval,
    EnvironmentVariables (names only), WorkingDirectory and RunAtLoad.
    Anything missing stays None. Nothing is guessed.
    """
    path = Path(path)
    try:
        with open(path, "rb") as handle:
            data = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None
    if not isinstance(data, dict):
        return None

    args = data.get("ProgramArguments")
    command: Optional[str] = None
    if isinstance(args, list) and args:
        command = " ".join(shlex.quote(str(item)) for item in args)
    elif isinstance(data.get("Program"), str):
        command = data["Program"]

    schedule_bits: list[str] = []
    calendar = _format_calendar_interval(data.get("StartCalendarInterval"))
    if calendar:
        schedule_bits.append(calendar)
    if isinstance(data.get("StartInterval"), int):
        schedule_bits.append(f"every {data['StartInterval']}s")
    if data.get("RunAtLoad") is True:
        schedule_bits.append("RunAtLoad")
    schedule = "; ".join(schedule_bits) if schedule_bits else None

    env: dict = {}
    env_vars = data.get("EnvironmentVariables")
    if isinstance(env_vars, dict):
        # Keep the names only. Values are dropped on the spot.
        env = {str(name): True for name in env_vars.keys()}

    working_dir = data.get("WorkingDirectory")
    if not isinstance(working_dir, str):
        working_dir = None

    label = data.get("Label")
    source = f"launchd:{label}" if isinstance(label, str) else f"launchd:{path.name}"

    return Job(
        source=source,
        schedule=schedule,
        command=command,
        env=env,
        working_dir=working_dir,
        raw_text=str(path),
    )


# ---------------------------------------------------------------------------
# systemd
# ---------------------------------------------------------------------------

_UNIT_KV_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*)$")


def _unit_pairs(text: str) -> list[tuple[str, str]]:
    """Return (Key, value) pairs from unit text. Sections and comments are skipped."""
    pairs: list[tuple[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped[0] in "#;[":
            continue
        match = _UNIT_KV_RE.match(stripped)
        if match:
            pairs.append((match.group(1), match.group(2).strip()))
    return pairs


def _env_names_from_file(path: Path) -> dict:
    """Return the variable NAMES declared in an EnvironmentFile. Values are dropped."""
    names: dict = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return names
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("export "):
            stripped = stripped[7:].lstrip()
        if stripped.startswith("#"):
            continue
        match = _CRON_ENV_RE.match(stripped)
        if match:
            names[match.group(1)] = True
    return names


def parse_systemd_unit(
    timer_text: str, service_text: str, source_label: str, service_dir=None
) -> Optional[Job]:
    """Build a Job from a .timer and its matching .service text.

    Schedule comes from OnCalendar, or from OnBootSec/OnUnitActiveSec when no
    calendar is set. Command is the first ExecStart. Environment= entries keep
    names only. EnvironmentFile= paths are read for names when they exist and
    are readable; relative paths resolve against service_dir.
    """
    calendar: list[str] = []
    monotonic: list[str] = []
    for key, value in _unit_pairs(timer_text or ""):
        if key == "OnCalendar" and value:
            calendar.append(value)
        elif key in ("OnBootSec", "OnUnitActiveSec", "OnStartupSec", "OnActiveSec") and value:
            monotonic.append(f"{key}={value}")
    schedule = "; ".join(calendar) if calendar else (" ".join(monotonic) or None)

    command: Optional[str] = None
    env: dict = {}
    working_dir: Optional[str] = None
    base = Path(service_dir) if service_dir else None
    for key, value in _unit_pairs(service_text or ""):
        if key == "ExecStart" and value and command is None:
            command = value.lstrip("-@+!: ").strip() or None
        elif key == "Environment":
            try:
                tokens = shlex.split(value)
            except ValueError:
                tokens = value.split()
            for token in tokens:
                name = token.split("=", 1)[0].strip()
                if _CRON_ENV_RE.match(name + "="):
                    env[name] = True  # value discarded here
        elif key == "EnvironmentFile" and value:
            target = Path(value.lstrip("-"))
            if not target.is_absolute() and base is not None:
                target = base / target
            if target.is_file() and os.access(target, os.R_OK):
                env.update(_env_names_from_file(target))
        elif key == "WorkingDirectory" and value:
            working_dir = value.lstrip("-")

    if command is None and schedule is None:
        return None
    return Job(
        source=source_label,
        schedule=schedule,
        command=command,
        env=env,
        working_dir=working_dir,
        raw_text=(timer_text or "") + "\n" + (service_text or ""),
    )


# ---------------------------------------------------------------------------
# GitHub Actions workflows (text scan, no yaml library)
# ---------------------------------------------------------------------------

_WF_CRON_RE = re.compile(r"""^\s*-?\s*cron:\s*['"]([^'"]+)['"]""")
_WF_NAME_RE = re.compile(r"""^name:\s*['"]?(.*?)['"]?\s*$""")
_WF_RUN_RE = re.compile(r"^(\s*)-?\s*run:\s*(.*?)\s*$")
_WF_ENV_RE = re.compile(r"^(\s*)env:\s*$")
_WF_KEY_RE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*):")
_WF_WORKDIR_RE = re.compile(r"""^\s*working-directory:\s*['"]?(.*?)['"]?\s*$""")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def parse_github_workflow(path) -> Optional[Job]:
    """Parse a workflow file by text. Returns None unless an on.schedule cron exists."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = text.splitlines()

    schedule: Optional[str] = None
    name: Optional[str] = None
    command: Optional[str] = None
    working_dir: Optional[str] = None
    env: dict = {}
    env_indent: Optional[int] = None

    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if env_indent is not None:
            if stripped and not stripped.startswith("#") and _indent(line) <= env_indent:
                env_indent = None
            else:
                key = _WF_KEY_RE.match(line)
                if key:
                    env[key.group(2)] = True  # name only, value discarded
                index += 1
                continue
        if schedule is None:
            cron = _WF_CRON_RE.match(line)
            if cron:
                schedule = cron.group(1).strip()
        if name is None:
            named = _WF_NAME_RE.match(line)
            if named:
                name = named.group(1)
        if working_dir is None:
            wd = _WF_WORKDIR_RE.match(line)
            if wd and wd.group(1):
                working_dir = wd.group(1)
        env_block = _WF_ENV_RE.match(line)
        if env_block:
            env_indent = len(env_block.group(1))
        run = _WF_RUN_RE.match(line)
        if run and command is None:
            value = run.group(2)
            if value and not value.startswith(("|", ">")):
                command = value.strip("'\"")
            else:
                run_indent = len(run.group(1))
                block: list[str] = []
                index += 1
                while index < len(lines):
                    body = lines[index]
                    if body.strip() and _indent(body) <= run_indent:
                        break
                    if body.strip():
                        block.append(body.strip())
                    index += 1
                command = "; ".join(block) if block else None
                continue
        index += 1

    if schedule is None:
        return None
    if command is None:
        command = name
    return Job(
        source=f"workflow:{path}",
        schedule=schedule,
        command=command,
        env=env,
        working_dir=working_dir,
        raw_text=str(path),
    )


# ---------------------------------------------------------------------------
# Claude scheduled tasks (known on-disk locations only, never guessed)
# ---------------------------------------------------------------------------


def _claude_jobs_from_json(path: Path, key: Optional[str] = None) -> list[Job]:
    """Turn a JSON task store into Jobs. Entries without both a schedule and a
    command are ignored. A broken or foreign file yields nothing."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if key is not None:
        data = data.get(key) if isinstance(data, dict) else None
    if isinstance(data, dict):
        data = data.get("tasks") or data.get("schedules")
    if not isinstance(data, list):
        return []
    jobs: list[Job] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        schedule = entry.get("schedule") or entry.get("cron")
        command = entry.get("command") or entry.get("prompt")
        if not isinstance(schedule, str) or not isinstance(command, str):
            continue
        env_block = entry.get("env")
        env = {str(k): True for k in env_block} if isinstance(env_block, dict) else {}
        cwd = entry.get("cwd") or entry.get("working_dir")
        jobs.append(
            Job(
                source=f"claude:{path.name}",
                schedule=schedule,
                command=command,
                env=env,
                working_dir=cwd if isinstance(cwd, str) else None,
                raw_text=str(path),
            )
        )
    return jobs


def probe_claude_tasks(home) -> list[Job]:
    """Look in the candidate locations for a Claude scheduled-task store.

    Returns [] when none exists, which is the normal case. Desktop app
    schedules live in app data and are not on disk in a stable place.
    """
    home = Path(home)
    jobs: list[Job] = []
    for sub in ("tasks", "schedules", "scheduled_tasks"):
        directory = home / ".claude" / sub
        if directory.is_dir():
            for entry in sorted(directory.glob("*.json")):
                jobs.extend(_claude_jobs_from_json(entry))
    config = home / ".claude.json"
    if config.is_file():
        jobs.extend(_claude_jobs_from_json(config, key="tasks"))
    return jobs


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def _discover_cron(args, home: Path) -> tuple[list[Job], list[str]]:
    """Find and parse crontab files. Missing or unreadable files are skipped."""
    cron_file = getattr(args, "cron_file", None)
    if cron_file:
        path = Path(cron_file)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return [], [f"cron: {cron_file} unreadable"]
        return parse_crontab_text(text, f"cron:{path}"), []

    candidates: list[Path] = [Path("/etc/crontab")]
    for directory in (Path("/etc/cron.d"), Path("/var/spool/cron/crontabs")):
        try:
            candidates.extend(sorted(directory.iterdir()))
        except OSError:
            pass
    candidates.append(home / ".config" / "cron" / "crontab")

    jobs: list[Job] = []
    for path in candidates:
        try:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        jobs.extend(parse_crontab_text(text, f"cron:{path}"))
    notes = [] if jobs else ["cron: no crontab files found"]
    return jobs, notes


def _discover_launchd(args, home: Path) -> tuple[list[Job], list[str]]:
    """Find and parse launchd plists from the override dir or the default dirs."""
    override = getattr(args, "launchd_dir", None)
    if override:
        directories = [Path(override)]
    else:
        directories = [
            home / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
            home / "Library" / "LaunchDaemons",
        ]

    jobs: list[Job] = []
    for directory in directories:
        try:
            if not directory.is_dir():
                continue
            plists = sorted(directory.glob("*.plist"))
        except OSError:
            continue
        for plist in plists:
            job = parse_launchd_plist(plist)
            if job is not None:
                jobs.append(job)
    notes = [] if jobs else ["launchd: no plist files found"]
    return jobs, notes


def _discover_systemd(args, home: Path) -> tuple[list[Job], list[str]]:
    """Find .timer units and pair each with its same-stem .service unit."""
    override = getattr(args, "systemd_dir", None)
    if override:
        directories = [Path(override)]
    else:
        directories = [
            home / ".config" / "systemd" / "user",
            Path("/etc/systemd/system"),
        ]

    jobs: list[Job] = []
    for directory in directories:
        try:
            if not directory.is_dir():
                continue
            timers = sorted(directory.glob("*.timer"))
        except OSError:
            continue
        for timer in timers:
            try:
                timer_text = timer.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            try:
                service_text = timer.with_suffix(".service").read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                service_text = ""
            job = parse_systemd_unit(
                timer_text,
                service_text,
                f"systemd:{timer.name}",
                service_dir=directory,
            )
            if job is not None:
                jobs.append(job)
    notes = [] if jobs else ["systemd: no timer units found"]
    return jobs, notes


def _discover_workflows(args) -> tuple[list[Job], list[str]]:
    """Walk the workflows root for .github/workflows files with a schedule."""
    root = Path(getattr(args, "workflows_root", None) or ".").resolve()
    root_depth = len(root.parts)

    jobs: list[Job] = []
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        if len(current.parts) - root_depth >= 4:
            dirnames[:] = []  # do not descend past 4 levels below root
        dirnames.sort()
        if current.name == "workflows" and current.parent.name == ".github":
            for filename in sorted(filenames):
                if filename.endswith((".yml", ".yaml")):
                    job = parse_github_workflow(current / filename)
                    if job is not None:
                        # Label with the path relative to the workflows root
                        # so output is the same on every machine.
                        job.source = (
                            f"workflow:{(current / filename).relative_to(root)}"
                        )
                        jobs.append(job)
    notes = [] if jobs else ["workflows: no scheduled workflows found"]
    return jobs, notes


def discover_jobs(args, home=None) -> tuple[list[Job], list[str]]:
    """Collect jobs from every source. Returns (jobs, notes).

    Jobs are ordered cron, launchd, systemd, workflows, claude. A missing
    source never raises; it adds a note instead.
    """
    home_path = Path(home) if home is not None else Path.home()

    cron_jobs, cron_notes = _discover_cron(args, home_path)
    launchd_jobs, launchd_notes = _discover_launchd(args, home_path)
    systemd_jobs, systemd_notes = _discover_systemd(args, home_path)
    workflow_jobs, workflow_notes = _discover_workflows(args)
    claude_jobs = probe_claude_tasks(home_path)
    claude_notes = [] if claude_jobs else ["claude: no scheduled-task store found"]

    jobs = cron_jobs + launchd_jobs + systemd_jobs + workflow_jobs + claude_jobs
    notes = (
        cron_notes + launchd_notes + systemd_notes + workflow_notes + claude_notes
    )
    return jobs, notes


def scan(args, home=None) -> tuple[list[Job], list[str]]:
    """Entry point for callers: discover every job and the notes about gaps."""
    return discover_jobs(args, home)


# ---------------------------------------------------------------------------
# Classifiers and scoring
# ---------------------------------------------------------------------------

AGENT_COMMANDS = (
    "claude",
    "codex",
    "gemini",
    "opencode",
    "aider",
    "crush",
    "goose",
    "amp",
    "cursor-agent",
)

_HIGH_PERMISSION_FLAGS = (
    "--dangerously-skip-permissions",
    "--allow-all",
    "-y",
    "--yes",
)

_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _tokenize_command(command: Optional[str]) -> list[str]:
    """Split a command line into tokens. Returns [] when empty or unparseable."""
    if not command:
        return []
    try:
        return shlex.split(command)
    except ValueError:
        return []


def _agent_name(command: Optional[str]) -> Optional[str]:
    """Return the agent CLI name a command invokes, or None if it is not one."""
    tokens = _tokenize_command(command)
    for token in tokens:
        if _ENV_ASSIGN_RE.match(token):
            continue
        name = token.rsplit("/", 1)[-1]
        return name if name in AGENT_COMMANDS else None
    return None


def _permission_mode_values(tokens: list[str]) -> list[str]:
    """Collect every value given to --permission-mode, in either spelling."""
    values: list[str] = []
    for index, token in enumerate(tokens):
        if token == "--permission-mode" and index + 1 < len(tokens):
            values.append(tokens[index + 1])
        elif token.startswith("--permission-mode="):
            values.append(token.split("=", 1)[1])
    return values


def _permission_level(command: Optional[str]) -> tuple[str, str]:
    """Return (level, detail) for the permission mode a command requests."""
    tokens = _tokenize_command(command)
    for token in tokens:
        if token in _HIGH_PERMISSION_FLAGS:
            return "HIGH", token
    modes = _permission_mode_values(tokens)
    if "bypassPermissions" in modes:
        return "HIGH", "--permission-mode bypassPermissions"
    if "acceptEdits" in modes:
        return "LOW", "--permission-mode acceptEdits"
    return "default", "default (prompts)"


def _working_dir_level(working_dir: Optional[str], home=None) -> tuple[str, str]:
    """Return (level, detail) for where a job runs. The path need not exist."""
    if not working_dir:
        return "unknown", "working directory unknown"
    home_path = Path(home) if home is not None else Path.home()
    try:
        home_resolved = home_path.expanduser().resolve()
        path = Path(working_dir).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return "unknown", "working directory unknown"

    text = str(path)
    if path == home_resolved:
        return "HIGH", "runs in the home directory"
    if path == Path("/") or text == "/":
        return "HIGH", "runs in the filesystem root"
    for part in path.parts:
        if part in ("prod", "production"):
            return "HIGH", f"path contains '{part}'"
    for prefix in ("/etc", "/var/www"):
        if text == prefix or text.startswith(prefix + "/"):
            return "HIGH", f"runs under {prefix}"

    try:
        if (path / ".git").exists():
            return "LOW", "repo dir (contains .git)"
    except OSError:
        pass
    try:
        path.relative_to(home_resolved)
        return "LOW", "under home dir"
    except ValueError:
        return "LOW", "bounded working dir"


BILLING_KEYS = {
    "claude": ("ANTHROPIC_API_KEY",),
    "codex": ("OPENAI_API_KEY",),
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "opencode": (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
    ),
}

BILLING_RULES = {
    "claude": (
        "Claude Code auth precedence: ANTHROPIC_API_KEY in the job env beats "
        "the subscription login. Key present means per-token API billing; "
        "key absent means the plan."
    ),
    "codex": (
        "Codex auth precedence: OPENAI_API_KEY in the job env beats the plan "
        "login. Key present means per-token API billing; key absent means "
        "the plan."
    ),
    "gemini": (
        "Gemini auth precedence: GEMINI_API_KEY or GOOGLE_API_KEY in the job "
        "env beats the plan login. Key present means per-token API billing; "
        "key absent means the plan."
    ),
    "opencode": (
        "Opencode bills a provider API key when one is in the job env, else "
        "the plan. Key present means per-token billing; key absent means "
        "the plan."
    ),
}


def _billing_verdict(agent: str, env: dict) -> tuple[str, str, str]:
    """Return (level, detail, rule) for who pays. Env names only, never values."""
    keys = BILLING_KEYS.get(agent)
    if keys is None:
        return (
            "unknown",
            f"no key mapping for {agent}",
            "No known API key mapping for this agent; billing path not verified.",
        )
    rule = BILLING_RULES[agent]
    for key in keys:
        if key in env:
            return "HIGH", f"bills API key (per-token), not subscription: {key}", rule
    return "LOW", "subscription/plan", rule


_GUARDRAIL_FLAGS = ("--max-turns", "--max-budget-usd", "--timeout")


def _has_guardrail(command: Optional[str]) -> bool:
    """True when the command carries a turn, budget or time limit flag."""
    for token in _tokenize_command(command):
        if token in _GUARDRAIL_FLAGS:
            return True
        if token.startswith(tuple(flag + "=" for flag in _GUARDRAIL_FLAGS)):
            return True
    return False


_EVERY_SECONDS_RE = re.compile(r"^every\s+(\d+)s$")


def _more_often_than_hourly(schedule: Optional[str]) -> bool:
    """True when the schedule fires more than once an hour. Unknown forms are False."""
    if not schedule:
        return False
    text = schedule.strip()
    every = _EVERY_SECONDS_RE.match(text)
    if every:
        return int(every.group(1)) < 3600
    if text.startswith("@"):
        return False
    fields = text.split()
    if len(fields) != 5:
        return False
    minute = fields[0]
    if minute == "*":
        return True
    if "," in minute:
        return len([part for part in minute.split(",") if part]) > 1
    if minute.startswith("*/"):
        step = minute[2:]
        return step.isdigit() and int(step) < 60
    if "-" in minute:
        return True
    return False


@dataclass
class Assessment:
    """The scored result for one Job. Names only, never secret values."""

    job: Job
    agent: Optional[str]
    permission: str
    permission_detail: str
    working_dir_level: str
    working_dir_detail: str
    billing: str
    billing_detail: str
    billing_rule: str
    guardrail_missing: bool
    frequent: bool
    severity: str
    reasons: list[str] = field(default_factory=list)


def score_job(job: Job, home=None) -> Assessment:
    """Score one job. Jobs that do not invoke a known agent CLI stay LOW."""
    agent = _agent_name(job.command)
    if agent is None:
        return Assessment(
            job=job,
            agent=None,
            permission="default",
            permission_detail="not an agent job",
            working_dir_level="unknown",
            working_dir_detail="not scored",
            billing="unknown",
            billing_detail="not an agent job",
            billing_rule="",
            guardrail_missing=False,
            frequent=False,
            severity="LOW",
            reasons=[],
        )

    permission, permission_detail = _permission_level(job.command)
    wd_level, wd_detail = _working_dir_level(job.working_dir, home)
    billing, billing_detail, billing_rule = _billing_verdict(agent, job.env)
    guardrail_missing = not _has_guardrail(job.command)
    frequent = _more_often_than_hourly(job.schedule)

    reasons: list[str] = []
    if permission == "HIGH":
        reasons.append(f"permission: {permission_detail}")
    if wd_level == "HIGH":
        reasons.append(f"working dir: {wd_detail}")
    if billing == "HIGH":
        reasons.append(f"billing: {billing_detail}")
    if guardrail_missing:
        reasons.append("no guardrail flag (max turns, budget or timeout)")
    if frequent:
        reasons.append("runs more often than hourly")

    if "HIGH" in (permission, wd_level, billing):
        severity = "HIGH"
    elif guardrail_missing or frequent:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return Assessment(
        job=job,
        agent=agent,
        permission=permission,
        permission_detail=permission_detail,
        working_dir_level=wd_level,
        working_dir_detail=wd_detail,
        billing=billing,
        billing_detail=billing_detail,
        billing_rule=billing_rule,
        guardrail_missing=guardrail_missing,
        frequent=frequent,
        severity=severity,
        reasons=reasons,
    )


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

_TABLE_HEADERS = (
    "SOURCE",
    "SCHEDULE",
    "COMMAND",
    "PERM",
    "WORKDIR",
    "BILLING",
    "SEVERITY",
)


def _truncate(text: Optional[str], width: int) -> str:
    """Return text if it fits in width, else cut it and end with '...'."""
    if text is None:
        text = "-"
    if len(text) <= width:
        return text
    return text[: width - 3] + "..."


def format_table(assessments: list[Assessment]) -> str:
    """Render agent assessments as an aligned text table. No trailing newline."""
    if not assessments:
        return "No agent jobs found."

    rows: list[list[str]] = [list(_TABLE_HEADERS)]
    for a in assessments:
        rows.append(
            [
                _truncate(a.job.source, 28),
                _truncate(a.job.schedule, 30),
                _truncate(a.job.command, 50),
                a.permission,
                a.working_dir_level,
                a.billing,
                a.severity,
            ]
        )

    widths = [max(len(row[col]) for row in rows) for col in range(len(_TABLE_HEADERS))]
    lines = ["  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip() for row in rows]
    separator = "-" * len(lines[0])
    return "\n".join([lines[0], separator] + lines[1:])


def assessment_to_dict(a: Assessment, explain: bool = False) -> dict:
    """Convert one Assessment to a JSON friendly dict. Env names are never included."""
    data = {
        "source": a.job.source,
        "schedule": a.job.schedule,
        "command": a.job.command,
        "agent": a.agent,
        "permission": a.permission,
        "permission_detail": a.permission_detail,
        "working_dir": a.working_dir_level,
        "working_dir_detail": a.working_dir_detail,
        "billing": a.billing,
        "billing_detail": a.billing_detail,
        "severity": a.severity,
        "guardrail_missing": a.guardrail_missing,
        "frequent": a.frequent,
        "reasons": list(a.reasons),
    }
    if explain:
        data["billing_rule"] = a.billing_rule
    return data


def _severity_counts(assessments: list[Assessment]) -> dict:
    """Count assessments by severity."""
    return {
        "high": sum(1 for a in assessments if a.severity == "HIGH"),
        "medium": sum(1 for a in assessments if a.severity == "MEDIUM"),
        "low": sum(1 for a in assessments if a.severity == "LOW"),
    }


def format_json(
    assessments: list[Assessment],
    non_agent_count: int,
    notes: list[str],
    explain: bool = False,
) -> str:
    """Render the full report as indented JSON."""
    payload = {
        "agent_jobs": [assessment_to_dict(a, explain=explain) for a in assessments],
        "non_agent_jobs": non_agent_count,
        "notes": notes,
        "summary": _severity_counts(assessments),
    }
    return json.dumps(payload, indent=2)


def main(argv=None, home=None) -> int:
    """Run the audit. Exit 1 when any agent job is HIGH, 2 on read errors, else 0.

    home overrides Path.home() for discovery; it exists so tests can run
    against an empty directory instead of the real machine.
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        jobs, notes = discover_jobs(args, home=home)
        assessments = [score_job(job) for job in jobs]
    except OSError as exc:
        print(f"nightshift: {exc}", file=sys.stderr)
        return 2

    agent_assessments = [a for a in assessments if a.agent is not None]
    non_agent_count = len(assessments) - len(agent_assessments)
    counts = _severity_counts(agent_assessments)

    if args.json:
        print(format_json(agent_assessments, non_agent_count, notes, explain=args.explain))
    else:
        print(format_table(agent_assessments))
        if args.explain:
            for a in agent_assessments:
                if a.billing_rule:
                    print(f"billing rule [{a.job.source}]: {a.billing_rule}")
        print(
            f"{len(agent_assessments)} agent jobs: {counts['high']} HIGH, "
            f"{counts['medium']} MEDIUM, {counts['low']} LOW; "
            f"{non_agent_count} non-agent jobs counted, not scored."
        )
        for note in notes:
            print(f"note: {note}")

    return 1 if counts["high"] else 0


if __name__ == "__main__":
    sys.exit(main())
