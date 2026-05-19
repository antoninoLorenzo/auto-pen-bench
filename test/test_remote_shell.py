import pytest
import paramiko

from autopenbench.shell import RemoteShell
# from autopenbench.shell.remote_shell_old import RemoteShell
from autopenbench.tools import wait_for_message
from autopenbench.driver.pentest_driver import restart_docker_compose_service

@pytest.fixture(scope="module")
def kali_shell_channel():
    restart_docker_compose_service("in-vitro_access_control_vm0")

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



_SHELL_NON_INTERACTIVE_TESTS = [
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


@pytest.mark.parametrize("test_case", _SHELL_NON_INTERACTIVE_TESTS)
def test_remote_shell(test_case, kali_shell_channel):
    shell = RemoteShell(shell=kali_shell_channel, **test_case["remote_shell_kwargs"])
    
    command = test_case["command"]
    output = shell.execute_cmd(command)

    output = output.replace(command, "").replace("\n", "")
    assert test_case["expected"] in output
