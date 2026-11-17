"""Unit tests for nightshift. Stdlib unittest only, no network.

Run from the repo root:  python3 -m unittest discover -s tests
"""

import contextlib
import io
import json
import plistlib
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import nightshift  # noqa: E402
from nightshift import (  # noqa: E402
    Assessment,
    Job,
    build_arg_parser,
    discover_jobs,
    main,
    parse_crontab_text,
    parse_github_workflow,
    parse_launchd_plist,
    parse_systemd_unit,
    probe_claude_tasks,
    scan,
    score_job,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

HIGH_CLAUDE_COMMAND = "claude -p --dangerously-skip-permissions do nightly work"
HIGH_CLAUDE_LINE = "*/15 * * * * " + HIGH_CLAUDE_COMMAND
RSYNC_LINE = "0 9 * * * rsync -a /src /dst"

CRONTAB_TEXT = (
    "# nightly agent jobs\n"
    "\n"
    "ANTHROPIC_API_KEY=secret\n"
    + HIGH_CLAUDE_LINE
    + "\n"
    "FOO=bar\n"
    + RSYNC_LINE
    + "\n"
)

CRON_DISCOVER_TEXT = (
    "ANTHROPIC_API_KEY=secret\n"
    + HIGH_CLAUDE_LINE
    + "\n"
    + RSYNC_LINE
    + "\n"
)

BENIGN_CRON_TEXT = "0 3 * * * codex exec --permission-mode acceptEdits --max-turns 3 tidy\n"

TIMER_TEXT = "[Timer]\nOnCalendar=daily\n"
SERVICE_TEXT = (
    "[Service]\n"
    "ExecStart=/usr/bin/claude -p work\n"
    "Environment=ANTHROPIC_API_KEY=secret\n"
    "WorkingDirectory=/srv/app\n"
)

GEMINI_TIMER_TEXT = "[Timer]\nOnCalendar=weekly\n"
GEMINI_SERVICE_TEXT = (
    "[Service]\n"
    "ExecStart=/usr/bin/gemini -p summarize\n"
    "EnvironmentFile=gemini.env\n"
)
GEMINI_ENV_TEXT = "GOOGLE_API_KEY=secret\n"

WORKFLOW_TEXT = (
    "name: Nightly agent\n"
    "on:\n"
    "  schedule:\n"
    "    - cron: '30 2 * * *'\n"
    "jobs:\n"
    "  work:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - name: Run agent\n"
    "        run: claude -p --max-turns 3 nightly\n"
    "        env:\n"
    "          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n"
)

WORKFLOW_NO_SCHEDULE_TEXT = (
    "name: On push\n"
    "on:\n"
    "  push:\n"
    "    branches: [main]\n"
    "jobs:\n"
    "  work:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - run: echo hello\n"
)

OPENCODE_WORKFLOW_TEXT = (
    "name: Opencode nightly\n"
    "on:\n"
    "  schedule:\n"
    "    - cron: '0 4 * * *'\n"
    "jobs:\n"
    "  work:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - run: opencode run tidy\n"
)


def write(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


class TestCrontabParsing(unittest.TestCase):
    def test_env_scoping_and_commands(self):
        jobs = parse_crontab_text(CRONTAB_TEXT, "cron:test")
        self.assertEqual(len(jobs), 2)
        first, second = jobs
        self.assertEqual(first.schedule, "*/15 * * * *")
        self.assertEqual(first.command, HIGH_CLAUDE_COMMAND)
        self.assertIn("ANTHROPIC_API_KEY", first.env)
        self.assertNotIn("FOO", first.env)
        self.assertIn("ANTHROPIC_API_KEY", second.env)
        self.assertIn("FOO", second.env)
        self.assertEqual(second.command, "rsync -a /src /dst")

    def test_rsync_is_not_an_agent_job(self):
        jobs = parse_crontab_text(CRONTAB_TEXT, "cron:test")
        self.assertIsNone(score_job(jobs[1]).agent)

    def test_special_schedule(self):
        jobs = parse_crontab_text("@daily claude -p tidy\n", "cron:test")
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].schedule, "@daily")
        self.assertEqual(jobs[0].command, "claude -p tidy")


class TestLaunchdParsing(TempDirCase):
    def test_parse_plist(self):
        data = {
            "Label": "com.example.agent",
            "ProgramArguments": [
                "claude", "-p", "--permission-mode", "bypassPermissions", "work",
            ],
            "StartInterval": 1800,
            "EnvironmentVariables": {"ANTHROPIC_API_KEY": "x"},
            "WorkingDirectory": "/Users/example",
        }
        path = self.tmp / "com.example.agent.plist"
        with open(path, "wb") as handle:
            plistlib.dump(data, handle)

        job = parse_launchd_plist(path)
        self.assertIsNotNone(job)
        self.assertIn("bypassPermissions", job.command)
        self.assertIn("every 1800s", job.schedule)
        self.assertEqual(job.env, {"ANTHROPIC_API_KEY": True})
        self.assertEqual(job.working_dir, "/Users/example")
        self.assertEqual(job.source, "launchd:com.example.agent")
        # The env value 'x' must not be stored anywhere in the Job.
        self.assertEqual(list(job.env.keys()), ["ANTHROPIC_API_KEY"])
        for value in job.env.values():
            self.assertIs(value, True)

    def test_corrupt_plist_returns_none(self):
        path = write(self.tmp / "broken.plist", "this is not a plist at all")
        self.assertIsNone(parse_launchd_plist(path))

    def test_missing_plist_returns_none(self):
        self.assertIsNone(parse_launchd_plist(self.tmp / "absent.plist"))


class TestSystemdParsing(unittest.TestCase):
    def test_parse_unit(self):
        job = parse_systemd_unit(TIMER_TEXT, SERVICE_TEXT, "systemd:t.timer")
        self.assertIsNotNone(job)
        self.assertEqual(job.schedule, "daily")
        self.assertIn("claude", job.command)
        self.assertEqual(job.env, {"ANTHROPIC_API_KEY": True})
        self.assertEqual(job.working_dir, "/srv/app")
        self.assertNotIn("=secret", job.command)

    def test_secret_value_absent(self):
        job = parse_systemd_unit(TIMER_TEXT, SERVICE_TEXT, "systemd:t.timer")
        self.assertNotIn("secret", repr(job.env))
        self.assertNotIn("secret", str(job.command))
        self.assertNotIn("secret", str(job.schedule))
        self.assertNotIn("secret", str(job.working_dir))

    def test_empty_returns_none(self):
        self.assertIsNone(parse_systemd_unit("", "", "systemd:none.timer"))


class TestWorkflowParsing(TempDirCase):
    def test_scheduled_workflow(self):
        path = write(self.tmp / "nightly.yml", WORKFLOW_TEXT)
        job = parse_github_workflow(path)
        self.assertIsNotNone(job)
        self.assertEqual(job.schedule, "30 2 * * *")
        self.assertIn("claude", job.command)
        self.assertIn("ANTHROPIC_API_KEY", job.env)

    def test_no_schedule_returns_none(self):
        path = write(self.tmp / "push.yml", WORKFLOW_NO_SCHEDULE_TEXT)
        self.assertIsNone(parse_github_workflow(path))


class TestClaudeProbe(TempDirCase):
    def test_probe_finds_task(self):
        entries = [
            {
                "schedule": "0 3 * * *",
                "command": "claude -p work",
                "env": {"ANTHROPIC_API_KEY": True},
            }
        ]
        write(self.tmp / ".claude" / "tasks" / "jobs.json", json.dumps(entries))
        jobs = probe_claude_tasks(self.tmp)
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].schedule, "0 3 * * *")
        self.assertEqual(jobs[0].command, "claude -p work")
        self.assertIn("ANTHROPIC_API_KEY", jobs[0].env)

    def test_probe_empty_home(self):
        self.assertEqual(probe_claude_tasks(self.tmp), [])


# ---------------------------------------------------------------------------
# Discovery and scoring
# ---------------------------------------------------------------------------


class TestDiscoverAndScore(TempDirCase):
    def setUp(self):
        super().setUp()
        self.home = self.tmp / "home"
        self.home.mkdir()

        self.cron_file = write(self.tmp / "cron" / "crontab", CRON_DISCOVER_TEXT)

        self.launchd_dir = self.tmp / "launchd"
        self.launchd_dir.mkdir()
        plist = {
            "Label": "com.example.codex",
            "ProgramArguments": [
                "codex", "exec", "--permission-mode", "acceptEdits",
                "--max-turns", "3", "tidy",
            ],
            "StartInterval": 7200,
            "EnvironmentVariables": {"PATH": "x"},
            "WorkingDirectory": str(self.tmp / "work"),
        }
        with open(self.launchd_dir / "com.example.codex.plist", "wb") as handle:
            plistlib.dump(plist, handle)

        self.systemd_dir = self.tmp / "systemd"
        write(self.systemd_dir / "gem.timer", GEMINI_TIMER_TEXT)
        write(self.systemd_dir / "gem.service", GEMINI_SERVICE_TEXT)
        write(self.systemd_dir / "gemini.env", GEMINI_ENV_TEXT)

        self.workflows_root = self.tmp / "repo"
        write(
            self.workflows_root / ".github" / "workflows" / "oc.yml",
            OPENCODE_WORKFLOW_TEXT,
        )

        self.args = Namespace(
            cron_file=str(self.cron_file),
            launchd_dir=str(self.launchd_dir),
            systemd_dir=str(self.systemd_dir),
            workflows_root=str(self.workflows_root),
        )

    def _jobs(self):
        jobs, notes = discover_jobs(self.args, home=self.home)
        return jobs, notes

    def _find(self, jobs, needle):
        matches = [j for j in jobs if needle in (j.command or "")]
        self.assertTrue(matches, f"no job with {needle!r}")
        return matches[0]

    def test_discover_finds_all_sources(self):
        jobs, _notes = self._jobs()
        assessments = [score_job(j, home=self.home) for j in jobs]
        agents = [a for a in assessments if a.agent is not None]
        self.assertGreaterEqual(len(agents), 4)
        self.assertEqual(
            {"claude", "codex", "gemini", "opencode"},
            {a.agent for a in agents},
        )

    def test_scan_matches_discover(self):
        scanned, _ = scan(self.args, home=self.home)
        discovered, _ = self._jobs()
        self.assertEqual(len(scanned), len(discovered))

    def test_high_claude_cron_job(self):
        jobs, _ = self._jobs()
        job = self._find(jobs, "dangerously-skip-permissions")
        a = score_job(job, home=self.home)
        self.assertIsInstance(a, Assessment)
        self.assertEqual(a.agent, "claude")
        self.assertEqual(a.severity, "HIGH")
        self.assertEqual(a.permission, "HIGH")
        self.assertEqual(a.billing, "HIGH")
        self.assertTrue(a.frequent)
        self.assertEqual(a.working_dir_level, "unknown")

    def test_home_working_dir_is_high(self):
        job = Job(
            source="test",
            schedule="0 3 * * *",
            command="claude -p work --max-turns 3",
            env={},
            working_dir=str(self.home),
        )
        a = score_job(job, home=self.home)
        self.assertEqual(a.working_dir_level, "HIGH")
        self.assertEqual(a.severity, "HIGH")

    def test_benign_codex_job_is_low(self):
        jobs, _ = self._jobs()
        job = self._find(jobs, "codex")
        a = score_job(job, home=self.home)
        self.assertEqual(a.agent, "codex")
        self.assertEqual(a.permission, "LOW")
        self.assertEqual(a.billing, "LOW")
        self.assertEqual(a.severity, "LOW")

    def test_gemini_env_file_names_only(self):
        jobs, _ = self._jobs()
        job = self._find(jobs, "gemini")
        self.assertIn("GOOGLE_API_KEY", job.env)
        a = score_job(job, home=self.home)
        self.assertEqual(a.billing, "HIGH")

    def test_rsync_scores_no_agent(self):
        jobs, _ = self._jobs()
        job = self._find(jobs, "rsync")
        a = score_job(job, home=self.home)
        self.assertIsNone(a.agent)
        self.assertEqual(a.severity, "LOW")

    def test_no_secret_values_leak(self):
        jobs, _ = self._jobs()
        for job in jobs:
            self.assertNotIn("secret", repr(job))
            a = score_job(job, home=self.home)
            self.assertNotIn("secret", str(a))
            self.assertNotIn("'x'", repr(job))
            self.assertNotIn("'x'", str(a))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestArgParser(unittest.TestCase):
    def test_defaults_and_flags(self):
        parser = build_arg_parser()
        args = parser.parse_args([])
        self.assertIsNone(args.cron_file)
        self.assertFalse(args.json)
        self.assertFalse(args.explain)
        args = parser.parse_args(["--json", "--explain", "--cron-file", "c"])
        self.assertTrue(args.json)
        self.assertTrue(args.explain)
        self.assertEqual(args.cron_file, "c")


class TestExitCodes(TempDirCase):
    def _run(self, argv):
        buffer = io.StringIO()
        empty = self.tmp / "empty"
        empty.mkdir(exist_ok=True)
        argv = list(argv) + [
            "--systemd-dir", str(empty),
            "--workflows-root", str(empty),
        ]
        with contextlib.redirect_stdout(buffer):
            code = main(argv, home=self.tmp)
        return code, buffer.getvalue()

    def test_benign_exit_zero(self):
        path = write(self.tmp / "benign.cron", BENIGN_CRON_TEXT)
        code, _out = self._run(["--cron-file", str(path)])
        self.assertEqual(code, 0)

    def test_high_exit_one(self):
        path = write(self.tmp / "high.cron", CRON_DISCOVER_TEXT)
        code, out = self._run(["--cron-file", str(path)])
        self.assertEqual(code, 1)
        self.assertNotIn("secret", out)


# ---------------------------------------------------------------------------
# Part 2: billing precedence, read-only guarantee, golden README output
# ---------------------------------------------------------------------------

import hashlib  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def _tree_hashes(root):
    hashes = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = Path(dirpath) / name
            digest = hashlib.sha256(full.read_bytes()).hexdigest()
            hashes[str(full.relative_to(root))] = digest
    return hashes


class TestBillingPrecedence(unittest.TestCase):
    def test_key_present_beats_absence(self):
        with_key = Job(
            source="cron:t",
            schedule="0 9 * * *",
            command="claude -p work",
            env={"ANTHROPIC_API_KEY": True},
        )
        without_key = Job(
            source="cron:t",
            schedule="0 9 * * *",
            command="claude -p work",
            env={},
        )
        self.assertEqual(score_job(with_key).billing, "HIGH")
        self.assertEqual(score_job(without_key).billing, "LOW")

    def test_env_file_key_counts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            env_path = write(Path(tmpdir) / "agent.env", "GOOGLE_API_KEY=whatever\n")
            timer = "[Timer]\nOnCalendar=daily\n"
            service = (
                "[Service]\n"
                "ExecStart=/usr/bin/gemini -p work\n"
                f"EnvironmentFile={env_path}\n"
            )
            job = parse_systemd_unit(timer, service, "systemd:t.timer")
            self.assertIsNotNone(job)
            a = score_job(job)
            self.assertEqual(a.agent, "gemini")
            self.assertEqual(a.billing, "HIGH")
            self.assertNotIn("whatever", repr(job))
            self.assertNotIn("whatever", str(a))

    def test_crontab_env_applies_below_only(self):
        text = (
            "0 9 * * * claude -p first\n"
            "ANTHROPIC_API_KEY=fake\n"
            "0 10 * * * claude -p second\n"
        )
        first, second = parse_crontab_text(text, "cron:t")
        self.assertNotIn("ANTHROPIC_API_KEY", first.env)
        self.assertIn("ANTHROPIC_API_KEY", second.env)
        self.assertEqual(score_job(first).billing, "LOW")
        self.assertEqual(score_job(second).billing, "HIGH")

    def test_explain_includes_rule(self):
        job = Job(
            source="cron:t",
            schedule="0 9 * * *",
            command="claude -p work",
            env={"ANTHROPIC_API_KEY": True},
        )
        a = score_job(job)
        self.assertEqual(a.billing, "HIGH")
        d = nightshift.assessment_to_dict(a, explain=True)
        self.assertIn("billing_rule", d)
        self.assertIn("ANTHROPIC_API_KEY", d["billing_rule"])
        self.assertNotIn("billing_rule", nightshift.assessment_to_dict(a))
        payload = json.loads(nightshift.format_json([a], 0, [], explain=True))
        self.assertIn("billing_rule", payload["agent_jobs"][0])


class TestReadOnly(TempDirCase):
    def test_scan_leaves_tree_unchanged(self):
        copy = self.tmp / "fixtures"
        shutil.copytree(ROOT / "fixtures", copy)
        before = _tree_hashes(copy)
        flags = {
            "cron_file": str(copy / "crontab"),
            "launchd_dir": str(copy / "launchd"),
            "systemd_dir": str(copy / "systemd"),
            "workflows_root": str(copy / "workflows"),
        }
        ns = Namespace(**flags)
        discover_jobs(ns, home=self.tmp)
        argv = [
            "--cron-file", flags["cron_file"],
            "--launchd-dir", flags["launchd_dir"],
            "--systemd-dir", flags["systemd_dir"],
            "--workflows-root", flags["workflows_root"],
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            main(argv, home=self.tmp)
        after = _tree_hashes(copy)
        self.assertEqual(before, after)


class TestGoldenOutput(TempDirCase):
    DEMO_ARGV = [
        "--cron-file", "fixtures/crontab",
        "--launchd-dir", "fixtures/launchd",
        "--systemd-dir", "fixtures/systemd",
        "--workflows-root", "fixtures/workflows",
    ]

    def test_readme_demo_matches_live_run(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        start_marker = "<!-- demo-output-start -->"
        end_marker = "<!-- demo-output-end -->"
        start = readme.index(start_marker) + len(start_marker)
        end = readme.index(end_marker, start)
        region = readme[start:end]
        fence = "`" * 3
        open_at = region.index(fence)
        body_start = region.index("\n", open_at) + 1
        close_at = region.index(fence, body_start)
        expected = region[body_start:close_at]
        if not expected.endswith("\n"):
            expected += "\n"

        old_cwd = os.getcwd()
        self.addCleanup(os.chdir, old_cwd)
        os.chdir(ROOT)

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(list(self.DEMO_ARGV), home=self.tmp)
        self.assertEqual(buffer.getvalue(), expected)
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
