import time

import pytest
import paramiko

from autopenbench.shell import RemoteShell
# from autopenbench.shell.remote_shell_old import RemoteShell
from autopenbench.tools import wait_for_message
from autopenbench.driver.pentest_driver import restart_docker_compose_service

@pytest.fixture(scope="module")
def restart_docker_compose():
    # restart_docker_compose_service("in-vitro_access_control_vm1")
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
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(
        '192.168.1.1',
        username='student',
        password='password',
        port=22
    )

    shell_channel = ssh_client.invoke_shell()
    wait_for_message(shell_channel)
    yield shell_channel


_SINGLE_COMMAND_TESTS = [
    {
        "remote_shell_kwargs": {"timeout": 10.0},
        "command": "sleep 5; echo 'hello'",
        "expected": "hello"
    },
    {
        "remote_shell_kwargs": {"timeout": 10.0},
        "command": "notexists",
        "expected": "command not found"
    },
]

def timed_out(actual: float, expected: float, eps: float = 0.2) -> bool:
    return actual >= expected - eps


@pytest.mark.parametrize("test_case", _SINGLE_COMMAND_TESTS)
def test_kali_single(test_case, kali_shell_channel):
    shell = RemoteShell(shell=kali_shell_channel, **test_case["remote_shell_kwargs"])
    timeout = shell.timeout

    command = test_case["command"]
    command_start = time.time()
    output = shell.execute_cmd(command)
    command_runtime = time.time() - command_start

    output = output.replace(command, "").replace("\n", "")
    assert test_case["expected"] in output
    assert timed_out(command_runtime, timeout) is False, f"Timed Out ({(command_runtime):.2f}): {command}"


@pytest.mark.parametrize("test_case", _SINGLE_COMMAND_TESTS)
def test_target_single(test_case, target_shell_channel):
    shell = RemoteShell(shell=target_shell_channel, **test_case["remote_shell_kwargs"])
    timeout = shell.timeout

    command = test_case["command"]
    command_start = time.time()
    output = shell.execute_cmd(command)
    command_runtime = time.time() - command_start

    output = output.replace(command, "").replace("\n", "")
    assert test_case["expected"] in output
    assert timed_out(command_runtime, timeout) is False, f"Timed Out ({(command_runtime):.2f}): {command}"


_SEQUENCE_TESTS = [
    {
        "machine": "target",
        "remote_shell_kwargs": {"timeout": 5.0},
        "commands": [
            "sleep 30",
            "id"
        ],
        "expected": [
            "",
            "uid=1000(student) gid=1000(student) groups=1000(student)"
        ]
    },
    {
        "machine": "kali",
        "remote_shell_kwargs": {"timeout": 5.0},
        "commands": [
            "sleep 30",
            "whoami"
        ],
        "expected": [
            "",
            "root"
        ]
    },
    {
        "machine": "target",
        "remote_shell_kwargs": {"timeout": 10.0},
        "commands": [
            "sudo -l",
            "password",
            "id"
        ],
        "expected": [
            "[sudo] password for student:",
            "Sorry, user student may not run sudo on",
            "uid=1000(student) gid=1000(student) groups=1000(student)"
        ]
    },
    {
        "machine": "kali",
        "remote_shell_kwargs": {"timeout": 20.0},
        "commands": [
            "msfconsole -q",
            "search geoserver",
            "use 2",
            "exit"
        ],
        "expected": [
            "msf >",
            "msf >",
            "msf exploit(multi/http/geoserver_unauth_rce_cve_2024_36401) >",
            "root@kali_master:~#"
        ]
    }
]

@pytest.mark.parametrize("test_case", _SEQUENCE_TESTS)
def test_command_sequences(test_case, kali_shell_channel, target_shell_channel):
    channel = kali_shell_channel if test_case["machine"] == "kali" else target_shell_channel
    shell = RemoteShell(shell=channel, **test_case["remote_shell_kwargs"])

    print('\n--- DEBUG ---\n')
    for command, expected in zip(test_case["commands"], test_case["expected"]):
        print(f"command={command}")
        result = shell.execute_cmd(command)
        print(f"result={result}")
        assert expected in result, f"Failed command: {command}"
