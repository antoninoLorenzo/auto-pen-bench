import re
import socket
import threading
import time

import pytest

from autopenbench.shell.remote_shell import (
    RemoteShell, 
    SENTINEL_RE, 
    TIMEOUT_MESSAGE, 
    EMPTY_COMMAND_MESSAGE,
    RECOVERY_SUCCESS_MESSAGE,
    RECOVERY_FAILED_MESSAGE,
)

# placeholder in a feed script's text, replaced by FakeChannel with the actual
# per-command sentinel RemoteShell generated (read back from what it sent).
SENTINEL = "<<SENTINEL>>"


class FakeChannel:
    """Mocks paramiko Channel.
    Use `program_response` to script the channel output.
    """

    def __init__(self):
        self._r, self._w = socket.socketpair()
        self._r.setblocking(False)
        self.sent = []
        self._last_sentinel = "" # sentinel in received command

    # paramiko Channel surface used by RemoteShell
    def fileno(self):
        return self._r.fileno()

    def recv_ready(self):
        import select
        return bool(select.select([self._r], [], [], 0)[0])

    def recv(self, n):
        try:
            return self._r.recv(n)
        except BlockingIOError:
            return b''

    def sendall(self, data):
        text = data.decode(errors='replace')
        self.sent.append(text)
        m = SENTINEL_RE.search(text)
        if m:
            self._last_sentinel = m.group(0)

    def send(self, data):
        self.sendall(data)
        return len(data)

    def close(self):
        try:
            self._r.close()
            self._w.close()
        except OSError:
            pass

    # test-side helpers
    def feed(self, text):
        self._w.sendall(text.encode())

    def feed_later(self, chunks):
        """chunks: list of (delay_seconds, text) pushed from a background thread."""
        def _run():
            for delay, text in chunks:
                time.sleep(delay)
                try:
                    self.feed(text)
                except OSError:
                    return  # socket closed at teardown; nothing left to test
        threading.Thread(target=_run, daemon=True).start()

    def program_response(self, script: list[dict]):
        """Arm a responder for the NEXT command RemoteShell sends.

        script: list of {"delay": float, "text": str}. 
        delay == 0 feeds as soon as the command is observed; delay > 0 sleeps first. 
        text may contain the SENTINEL placeholder replaced with the observed command 
        sentinel.
        """
        baseline = len(self.sent)

        def _run():
            # wait until RemoteShell actually sends this step's command, so the
            # sentinel it embedded is available for substitution.
            deadline = time.monotonic() + 15.0
            while len(self.sent) <= baseline and time.monotonic() < deadline:
                time.sleep(0.005)
            for step in script:
                delay = step.get("delay", 0)
                if delay > 0:
                    time.sleep(delay)
                text = step["text"].replace(SENTINEL, self._last_sentinel)
                try:
                    self.feed(text)
                except OSError:
                    return

        threading.Thread(target=_run, daemon=True).start()


class _NoSetupRemoteShell(RemoteShell):
    # poor man's monkeypatch (aka private name mangling):
    # RemoteShell.__start_session requires the actual shell.
    def _RemoteShell__start_session(self):
        pass


@pytest.fixture
def shell():
    chan = FakeChannel()
    sh = _NoSetupRemoteShell(shell=chan, timeout=2.0)
    yield sh
    chan.close()


def _read(sh):
    return sh._RemoteShell__read()


def _read_interactive(sh):
    return sh._RemoteShell__read_interactive()


# real shells terminate lines with CRLF; feed CRLF so pyte renders clean lines
# (a bare \n line-feeds without a carriage return and would staircase).
def _body(text):
    return text.replace("\n", "\r\n")


def _default_feed(expected):
    """Feed derived from `expected` when a case gives no explicit feed.

    - TIMEOUT_MESSAGE -> [] (withhold the sentinel; non-interactive read times out)
    - str            -> echo the body then the sentinel (command completed)
    - callable       -> unsupported; such a case must provide an explicit feed.
    """
    if callable(expected):
        raise ValueError("callable 'expected' needs an explicit feed script")
    if expected == TIMEOUT_MESSAGE:
        return []
    return [{"delay": 0, "text": _body(expected) + "\r\n" + SENTINEL + "\r\n"}]


def _assert_expected(result, expected):
    if callable(expected):
        assert expected(result), f"predicate failed on {result!r}"
    else:
        assert expected in result, f"expected {expected!r} in {result!r}"


NON_INTERACTIVE_SEQUENCES = [
    {
        # if a command prints to stderr the agent needs a signal to know the mistake
        "name": "SC_CaptureStderr",
        "remote_shell_kwargs": {"timeout": 5.0},
        "commands": [
            {"cmd": "echo '1'; echo '2' 1>&2", "interactive": False},
        ],
        "expected": [
            "1\n2",
        ],
    },
    {
        # progress bars work using `\r`; the risk is having rendering strip it and
        # print "Progress 0/50 Progress 1/50 ... Progress 50/50" that would bloat
        # the context window; that was an issue observed with previous
        # implementations that didn't use pyte, so this is mostly anti-regression.
        "name": "SC_ProgressBarRendering",
        "remote_shell_kwargs": {"timeout": 5.0},
        "commands": [
            {"cmd": r'for i in $(seq 1 50); do sleep 0.05; printf "\rProgress: %d/50" "$i"; done; printf "\n"',
             "interactive": False},
        ],
        "expected": [
            lambda out: "Progress: 50/50" in out and len(out) <= 20,
        ],
        "feed": [
            [
                {"delay": 0.0, "text": "\rProgress: 1/50"},
                {"delay": 0.05, "text": "\rProgress: 2/50"},
                {"delay": 0.05, "text": "\rProgress: 25/50"},
                {"delay": 0.05, "text": "\rProgress: 50/50\r\n" + SENTINEL + "\r\n"},
            ],
        ],
    },
    {
        # another potential cause of context bloat is faulty rendering where colors
        # aren't properly parsed
        "name": "SC_NoColors",
        "remote_shell_kwargs": {"timeout": 5.0},
        "commands": [
            {"cmd": r"printf '\033[31mred\033[0m\n'", "interactive": False},
        ],
        "expected": [
            "red",
        ],
        "feed": [
            [{"delay": 0.0, "text": "\033[31mred\033[0m\r\n" + SENTINEL + "\r\n"}],
        ],
    },
    {
        # in non-interactive mode a command that times out should be stopped to
        # leave the shell usable: 'leak' must not reach stdout and the second echo
        # should execute as if nothing happened. The fake withholds the sentinel
        # for cmd0 (empty feed) so the read runs to timeout.
        "name": "TimeoutRecoveryBase",
        "remote_shell_kwargs": {"timeout": 2.0},
        "commands": [
            {"cmd": "sleep 30; echo 'leak'", "interactive": False},
            {"cmd": "echo 'TimeoutTest'", "interactive": False},
        ],
        "expected": [
            TIMEOUT_MESSAGE,
            "TimeoutTest",
        ],
    },
    {
        # a program that ignores SIGINT should still be stopped. At the fake level
        # this is identical to TimeoutRecoveryBase (withhold sentinel -> timeout);
        # the REAL SIGINT-blocked recovery (needs Ctrl-\ / SIGKILL escalation) is
        # only verifiable in the integration suite against a live shell.
        "name": "TimeoutRecoveryBlockedSIGINT",
        "remote_shell_kwargs": {"timeout": 2.0},
        "commands": [
            {"cmd": "trap '' INT; sleep 30; echo 'leak'", "interactive": False},
            {"cmd": "echo 'TimeoutTest'", "interactive": False},
        ],
        "expected": [
            TIMEOUT_MESSAGE,
            "TimeoutTest",
        ],
    },
    {
        # the output of a background job must not leak into later commands; the
        # desired behaviour is that the agent redirects it to a file. cmd0 returns
        # only the job-control line ("[1] <pid>").
        "name": "BackgroundJobNoLeak",
        "remote_shell_kwargs": {"timeout": 5.0},
        "commands": [
            {"cmd": "(sleep 1; echo 'background' > /tmp/foo) &", "interactive": False},
            {"cmd": "echo 'after'", "interactive": False},
        ],
        "expected": [
            lambda out: re.search(r"\[\d+\]\s+\d+", out) is not None,
            "after",
        ],
        "feed": [
            [{"delay": 0.0, "text": "[1] 12345\r\n" + SENTINEL + "\r\n"}],
            None,  # -> default feed for "after"
        ],
    },
    {
        # a non-interactive command run WITH interactive=True must still terminate
        # via the sentinel: the interactive read checks the sentinel exit condition
        # too. This is the one non-interactive case flagged interactive (the launch
        # command carries the sentinel because is_interactive starts False).
        "name": "SC_InteractiveFlagHitsSentinel",
        "remote_shell_kwargs": {"timeout": 5.0, "max_silence": 0.3},
        "commands": [
            {"cmd": "echo hi", "interactive": True},
        ],
        "expected": [
            "hi",
        ],
    },
]

INTERACTIVE_SEQUENCES = [
    {
        # enter a REPL, run a command inside it, exit. The launch command carries
        # the sentinel (is_interactive starts False) but the fake withholds it
        # while the program runs; only the `exit` step echoes the sentinel, so the
        # interactive read detects the exit and clears is_interactive.
        "name": "REPL_EnterInteractExit",
        # realistic timings: a live msfconsole launch dribbles its banner for
        # several seconds, so a small timeout/max_silence (fine for the scripted
        # unit feed) makes the live run time out or settle mid-banner.
        "remote_shell_kwargs": {"timeout": 40.0, "max_silence": 2.0},
        "commands": [
            {"cmd": "msfconsole -q", "interactive": True},
            {"cmd": "version", "interactive": True},
            {"cmd": "exit", "interactive": True},
        ],
        "expected": [
            "msf",
            "Framework",
            "",  # exit -> back to shell (sentinel stripped)
        ],
        "feed": [
            [{"delay": 0.0, "text": "\r\n[*] Metasploit tip: ...\r\nmsf6 > "}],
            [{"delay": 0.0, "text": "Framework: 6.4.0\r\nmsf6 > "}],
            [{"delay": 0.0, "text": SENTINEL + "\r\n"}],
        ],
    },
    {
        # the interactive read must not return early: output arrives in chunks with
        # gaps shorter than max_silence, then goes quiet. All lines must be present
        # (a missing later line would mean an early return). No sentinel: the
        # program keeps running and the read settles on max_silence.
        "name": "Interactive_ChunkedNoEarlyReturn",
        "unit_only": True,  # byte-timing simulation; no live-command equivalent
        "remote_shell_kwargs": {"timeout": 5.0, "max_silence": 0.4},
        "commands": [
            {"cmd": "python3", "interactive": True},
        ],
        "expected": [
            lambda out: all(x in out for x in ("line1", "line2", "line3")),
        ],
        "feed": [
            [
                {"delay": 0.0, "text": "line1\r\n"},
                {"delay": 0.1, "text": "line2\r\n"},
                {"delay": 0.1, "text": "line3\r\n"},
            ],
        ],
    },
    {
        # a program that prints a prompt with no trailing newline and waits for
        # input (the launch settles on max_silence); the reply returns to the shell
        # and the pending sentinel prints, ending the sequence.
        "name": "Interactive_PasswordPrompt",
        "machine": "target",
        "remote_shell_kwargs": {"timeout": 5.0, "max_silence": 0.3},
        "commands": [
            {"cmd": "sudo -l", "interactive": True},
            {"cmd": "password", "interactive": True},
        ],
        "expected": [
            "[sudo] password",
            "Sorry, user",
        ],
        "feed": [
            [{"delay": 0.0, "text": "[sudo] password for student: "}],
            [{"delay": 0.0, "text": "\r\nSorry, user student may not run sudo on host.\r\n" + SENTINEL + "\r\n"}],
        ],
    },
    {
        # guardrail: an interactive program launched with interactive=False is read
        # non-interactively, so it is only stopped by the timeout. cmd0 withholds
        # the sentinel (banner, no sentinel) -> TIMEOUT_MESSAGE; the shell recovers
        # for cmd1.
        "name": "Interactive_UnflaggedTimesOut",
        "remote_shell_kwargs": {"timeout": 2.0, "max_silence": 0.3},
        "commands": [
            {"cmd": "msfconsole -q", "interactive": False},
            {"cmd": "echo recovered", "interactive": False},
        ],
        "expected": [
            TIMEOUT_MESSAGE,
            "recovered",
        ],
        "feed": [
            [{"delay": 0.0, "text": "\r\n[*] Metasploit banner\r\nmsf6 > "}],  # no sentinel
            None,
        ],
    },
]

COMMAND_SEQUENCES = [
    {
        "name": "Interleaved_ReplRoundTrip",
        "remote_shell_kwargs": {"timeout": 5.0, "max_silence": 0.3},
        "commands": [
            {"cmd": "whoami", "interactive": False},
            {"cmd": "msfconsole -q", "interactive": True},
            {"cmd": "search geoserver", "interactive": True},
            {"cmd": "exit", "interactive": True},
            {"cmd": "echo done", "interactive": False},
        ],
        "expected": [
            "root",
            "msf",
            "geoserver",
            "",
            "done",
        ],
        "feed": [
            None,  # whoami -> "root"
            [{"delay": 0.0, "text": "\r\n[*] banner\r\nmsf6 > "}],
            [{"delay": 0.0, "text": "Matching Modules\r\n  exploit/multi/http/geoserver_unauth_rce\r\nmsf6 > "}],
            [{"delay": 0.0, "text": SENTINEL + "\r\n"}],
            None,  # echo done -> "done" (fresh sentinel, shell usable again)
        ],
    },
]


def _run_sequence(test_case):
    chan = FakeChannel()
    sh = _NoSetupRemoteShell(shell=chan, **test_case["remote_shell_kwargs"])
    try:
        commands = test_case["commands"]
        expected = test_case["expected"]
        feeds = test_case.get("feed") or [None] * len(commands)

        print(f"\n### --- {test_case.get('name', '?')}")
        for i, (cmd_spec, exp) in enumerate(zip(commands, expected)):
            feed = feeds[i] if i < len(feeds) else None
            script = feed if feed is not None else _default_feed(exp)

            chan.program_response(script)  # arm BEFORE execute_cmd
            result = sh.execute_cmd(cmd_spec["cmd"], interactive=cmd_spec.get("interactive", False))
            print(f"cmd={cmd_spec['cmd']!r} interactive={cmd_spec.get('interactive', False)} -> {result!r}")

            _assert_expected(result, exp)
    finally:
        chan.close()


@pytest.mark.parametrize("test_case", NON_INTERACTIVE_SEQUENCES, ids=lambda c: c["name"])
def test_non_interactive_sequences(test_case):
    _run_sequence(test_case)


@pytest.mark.parametrize("test_case", INTERACTIVE_SEQUENCES, ids=lambda c: c["name"])
def test_interactive_sequences(test_case):
    _run_sequence(test_case)


@pytest.mark.parametrize("test_case", COMMAND_SEQUENCES, ids=lambda c: c["name"])
def test_command_sequences(test_case):
    _run_sequence(test_case)


def test_empty_command_returns_guard(shell):
    assert shell.execute_cmd("") == EMPTY_COMMAND_MESSAGE

def test_non_string_command_returns_guard(shell):
    assert shell.execute_cmd(None) == EMPTY_COMMAND_MESSAGE


# The Ctrl+C escape hatch is soft SIGINT only. The recovery outcome depends on
# __shell_is_ready, whose probe uses a fresh random nonce the scripted
# FakeChannel cannot echo generically, so we stub __send_sigint to drive each
# branch and assert the message + state bookkeeping execute_cmd is responsible
# for.
@pytest.mark.parametrize("spelling", ["Ctrl+C", "Ctrl-C"])
def test_ctrl_c_escape_hatch_recovers(shell, spelling):
    shell.is_interactive = True
    shell._sentinel = "apb:stale:end"
    shell._RemoteShell__send_sigint = lambda: True  # SIGINT brought the prompt back

    assert shell.execute_cmd(spelling) == RECOVERY_SUCCESS_MESSAGE
    assert shell.is_interactive is False
    assert shell._sentinel is None


def test_ctrl_c_escape_hatch_reports_failure(shell):
    shell._RemoteShell__send_sigint = lambda: False  # program ignored SIGINT

    assert shell.execute_cmd("Ctrl+C") == RECOVERY_FAILED_MESSAGE
