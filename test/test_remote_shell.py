# integration tests for RemoteShell against the live docker network.
import os
import sys
import time

import pytest
import paramiko

from autopenbench.shell import RemoteShell
from autopenbench.shell.remote_shell import TIMEOUT_MESSAGE
from autopenbench.tools import wait_for_message
from autopenbench.driver.pentest_driver import restart_docker_compose_service

# import the shared, parametrized sequences + assertion helper from the unit suite
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_remote_shell_unit import (  # noqa: E402
    NON_INTERACTIVE_SEQUENCES,
    INTERACTIVE_SEQUENCES,
    COMMAND_SEQUENCES,
    _assert_expected as assert_expected,
)


@pytest.fixture(scope="module")
def restart_docker_compose():
    restart_docker_compose_service("in-vitro_access_control_vm1")
    pass


@pytest.fixture(scope="module")
def kali_shell_channel(restart_docker_compose):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(
        '192.168.0.5',
        username='root',
        password='root',
        port=22
    )

    shell_channel = ssh_client.invoke_shell()
    wait_for_message(shell_channel)
    yield shell_channel


@pytest.fixture(scope="module")
def target_shell_channel(restart_docker_compose):
    # Within the benchmark connection to target happens through Kali (see also
    # `autopenbench.tools.ssh_connect.SSHConnect`).
    # This also solves the issue where target addresses conflict with network
    # addresses.
    jump = paramiko.SSHClient()
    jump.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    jump.connect(
        '192.168.0.5',
        username='root',
        password='root',
        port=22
    )

    tunnel = jump.get_transport().open_channel(
        'direct-tcpip',
        dest_addr=('192.168.1.1', 22),
        src_addr=('127.0.0.1', 0)
    )

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(
        '192.168.1.1',
        username='student',
        password='password',
        port=22,
        sock=tunnel
    )

    shell_channel = ssh_client.invoke_shell()
    wait_for_message(shell_channel)
    yield shell_channel

    ssh_client.close()
    jump.close()


def _live(seqs):
    return [c for c in seqs if not c.get("unit_only")]


# live-only non-interactive: things a real shell shows that the fake can't
# meaningfully assert (command-not-found text, real timeout recovery).
NON_INTERACTIVE_EXTRA = [
    {
        "name": "SC_CommandNotFound",
        "machine": "kali",
        "remote_shell_kwargs": {"timeout": 5.0},
        "commands": [{"cmd": "notexists", "interactive": False}],
        "expected": ["command not found"],
    },
    {
        "name": "TimeoutThenClean_target",
        "machine": "target",
        "remote_shell_kwargs": {"timeout": 5.0},
        "commands": [
            {"cmd": "sleep 30", "interactive": False},
            {"cmd": "id", "interactive": False},
        ],
        "expected": [
            TIMEOUT_MESSAGE,
            "uid=1000(student)",
        ],
    },
]

# live-only interactive: the real REPL / sudo flows that motivated the rewrite.
INTERACTIVE_EXTRA = [
    {
        "name": "Sudo_L_Target_FullFlow",
        "machine": "target",
        "remote_shell_kwargs": {"timeout": 10.0},
        "commands": [
            {"cmd": "sudo -l", "interactive": True},
            {"cmd": "password", "interactive": True},
            {"cmd": "id", "interactive": False},
        ],
        "expected": [
            "[sudo] password for student:",
            "Sorry, user student may not run sudo on",
            "uid=1000(student)",
        ],
    },
    {
        "name": "Msfconsole_Geoserver_Kali",
        "machine": "kali",
        "remote_shell_kwargs": {"timeout": 40.0, "max_silence": 2.0},
        "commands": [
            {"cmd": "msfconsole -q", "interactive": True},
            {"cmd": "search geoserver", "interactive": True},
            # Select by full module name, not a numeric index: the search
            # ordering shifts whenever the msf module DB changes.
            {"cmd": "use exploit/multi/http/geoserver_unauth_rce_cve_2024_36401", "interactive": True},
            {"cmd": "exit", "interactive": True},
        ],
        "expected": [
            "msf",
            "geoserver",
            "geoserver_unauth_rce_cve_2024_36401",
            "",
        ],
    },
]


def _run_live_sequence(test_case, kali_shell_channel, target_shell_channel):
    channel = kali_shell_channel if test_case.get("machine", "kali") == "kali" else target_shell_channel
    shell = RemoteShell(shell=channel, **test_case["remote_shell_kwargs"])

    print(f"\n--- DEBUG [{test_case.get('name', '?')}] ---")
    for cmd_spec, expected in zip(test_case["commands"], test_case["expected"]):
        result = shell.execute_cmd(cmd_spec["cmd"], interactive=cmd_spec.get("interactive", False))
        print(f"cmd={cmd_spec['cmd']!r} interactive={cmd_spec.get('interactive', False)} -> {result!r}")
        assert_expected(result, expected)


@pytest.mark.parametrize(
    "test_case", _live(NON_INTERACTIVE_SEQUENCES) + NON_INTERACTIVE_EXTRA,
    ids=lambda c: c["name"],
)
def test_non_interactive_sequences_live(test_case, kali_shell_channel, target_shell_channel):
    _run_live_sequence(test_case, kali_shell_channel, target_shell_channel)


@pytest.mark.parametrize(
    "test_case", _live(INTERACTIVE_SEQUENCES) + INTERACTIVE_EXTRA,
    ids=lambda c: c["name"],
)
def test_interactive_sequences_live(test_case, kali_shell_channel, target_shell_channel):
    _run_live_sequence(test_case, kali_shell_channel, target_shell_channel)


@pytest.mark.parametrize(
    "test_case", _live(COMMAND_SEQUENCES),
    ids=lambda c: c["name"],
)
def test_command_sequences_live(test_case, kali_shell_channel, target_shell_channel):
    _run_live_sequence(test_case, kali_shell_channel, target_shell_channel)
