import re
import time
import uuid
import select
import signal

import paramiko
import pyte

MAX_TIMEOUT_S = 300.0
MAX_SILENCE_S = 10.0

TIMEOUT_MESSAGE = f"The command exceeded the execution time limit ({MAX_TIMEOUT_S}s)."
RECOVERY_SUCCESS_MESSAGE = "Stopped command execution."
RECOVERY_FAILED_MESSAGE = "Couldn't stop command execution."
EMPTY_COMMAND_MESSAGE = "The command provided is empty."

# per-command end sentinel follows format `apb:<hex>:end`.
SENTINEL_RE = re.compile(r"apb:[0-9a-f]+:end")


class RemoteShell:

    def __init__(
        self,
        shell: paramiko.Channel,
        timeout: float = MAX_TIMEOUT_S,
        max_silence: float = MAX_SILENCE_S
    ):
        self.shell = shell
        self.timeout = timeout
        self.max_silence = max_silence
        
        self._screen_width = 1000
        self._sentinel_template = "apb:{nonce}:end"

        # sentinel of current program 
        self._sentinel = None
        # set to True when an interactive command arrives so subsequent commands 
        # are sent without sentinel wrapping to the interactive program, reset 
        # to False when interactive read finds the sentinel
        self.is_interactive = False

        self.__start_session()

    def execute_cmd(self, cmd: str, interactive: bool = False) -> str:
        if not isinstance(cmd, str) or len(cmd) == 0:
            return EMPTY_COMMAND_MESSAGE

        # explicit interrupt escape hatch: soft SIGINT only, never force-kill.
        if cmd.strip() in ('Ctrl+C', 'Ctrl-C'):
            if self.__send_sigint():
                self.is_interactive = False
                self._sentinel = None
                return RECOVERY_SUCCESS_MESSAGE
            return RECOVERY_FAILED_MESSAGE

        nonce = uuid.uuid4().hex[:12]
        sentinel = self._sentinel_template.format(nonce=nonce)
        try:
            if self.is_interactive:
                command = cmd + '\n'
            else:
                command = "{\n" + cmd + "\n}; " + f'printf "%s" "{sentinel}"' + "\n"
                self._sentinel = sentinel 

            # arm the sentinel only on the command that enters the REPL, so its
            # trailing printf fires when the program exits and toggles the latch
            if interactive and not self.is_interactive:
                self._sentinel = sentinel
                self.is_interactive = True

            if interactive or self.is_interactive:
                # sticky: once a REPL is active, follow-up commands sent with
                # interactive=False are still read interactively (they would
                # otherwise block in __read waiting for the launch sentinel)
                self.shell.sendall(command.encode())
                return self.__read_interactive()
            else:
                # wrap so a multi line / multi statement command is one compound
                # command and produces a single trailing sentinel
                self.shell.sendall(command.encode())
                return self.__read()
        except Exception as send_err:
            return str(send_err)

    def close(self):
        try:
            self.shell.close()
        except Exception:
            pass

    def __start_session(self):
        # Setup of the remote shell on the target machine:
        # 
        # * non-interactive programs and the command that starts an interactive 
        # program are wrapped to print a per command completion sentinel to stop 
        # reading from the channel, echo needs to be disabled with `stty -echo` 
        # and `bash --noediting`.
        # 
        # * to consistently render a program output without line-wrapping, set 
        # screen width using `stty cols {self._screen_width}`.
        # 
        # * backgrounded jobs notify completion asynchronously even if redirected, 
        # to avoid pollution of command output disable monitor mode with `set +m`.
        # 
        # * non-interactive commands are wrapped and PS2 is empty to avoid issues 
        # with multiline commands
        self._raw_idle_drain() # consume login shell banner

        self.shell.sendall(b"exec bash --noediting\n")
        self._raw_idle_drain()
        
        setup = (
            "stty -echo 2>/dev/null; "
            f"stty cols {self._screen_width} 2>/dev/null; "
            "PS1=''; PS2=''\n"
        )
        self.shell.sendall(setup.encode())
        self._raw_idle_drain()

        self.shell.sendall(b"\n")
        self._raw_idle_drain()

    def __read(self) -> str:
        buffer = bytes()
        start = time.monotonic()

        while True:
            new_bytes = self._select_recv()
            if new_bytes is not None:
                buffer += new_bytes

            text = self._decode_clean(buffer)
            if self._sentinel in text:
                return self._strip_sentinel(text, self._sentinel)

            now = time.monotonic()
            if now - start >= self.timeout:
                # strip before __restore_shell, which clears self._sentinel
                text = self._strip_sentinel(text, self._sentinel)
                recovery_err = self.__restore_shell()
                return text + "\n" + TIMEOUT_MESSAGE + recovery_err

    def __read_interactive(self) -> str:
        buffer = bytes()
        start = time.monotonic()
        last_activity = start

        while True:
            new_bytes = self._select_recv()
            now = time.monotonic()
            if new_bytes is not None:
                buffer += new_bytes
                last_activity = now
            
            text = self._decode_clean(buffer)
            # interactive program returned control to shell
            if self._sentinel in text:
                self.is_interactive = False
                return self._strip_sentinel(text, self._sentinel)

            if now - start >= self.timeout:
                return self._strip_sentinel(text, self._sentinel) + "\n" + TIMEOUT_MESSAGE

            # stop read heuristic: wait for at least some visible output, then
            # return if nothing new arrived in the last max_silence window.
            if text.strip() and (now - last_activity) >= self.max_silence:
                return self._strip_sentinel(text, self._sentinel)

    def __shell_is_ready(self, timeout: float) -> bool:
        """
        :returns: False if a program is holding the terminal, True otherwise.
        """
        sentinel = self._sentinel_template.format(nonce=uuid.uuid4().hex[:12])
        try:
            self.shell.sendall(f'printf "%s" "{sentinel}"\n'.encode())
        except Exception:
            return False

        buffer = bytes()
        start = time.monotonic()

        while time.monotonic() - start < timeout:
            new_bytes = self._select_recv()
            if new_bytes is not None:
                buffer += new_bytes

                if sentinel in self._decode_clean(buffer):
                    return True
                    
        return False

    def __send_sigint(self, step_timeout: float = 2.0) -> bool:
        """
        :returns: False if the shell prompt is unresponsive, otherwise True.
        """
        try:
            self.shell.sendall(b'\x03')
        except Exception:
            return False
        return self.__shell_is_ready(step_timeout)

    def __restore_shell(self, step_timeout: float = 2.0) -> str:
        """
        Recover shell state after non-interactive timeout.
        :returns: error message if recovery failed, empty string otherwise.
        """
        recovered = self.__send_sigint(step_timeout)
        if recovered:
            return ""

        # suspend + SIGKILL the job
        try:
            self.shell.sendall(b'\x1a')                       # Ctrl+Z -> SIGTSTP
            self.shell.sendall(b'kill -9 %% 2>/dev/null\n')   # SIGKILL the stopped job
        except Exception as err:
            return str(err)

        self._raw_idle_drain()
        recovered = self.__shell_is_ready(step_timeout)
        self._raw_idle_drain()

        self.is_interactive = False
        self._sentinel = None

        return "" if recovered else RECOVERY_FAILED_MESSAGE

    def _raw_idle_drain(self, idle: float = 0.4, max_wait: float = 8.0):
        start = time.monotonic()
        last = start
        while True:
            readable, _, _ = select.select([self.shell], [], [], 0.1)
            if readable and self.shell.recv_ready():
                self._recv_available()
                last = time.monotonic()
            now = time.monotonic()
            if now - last >= idle or now - start >= max_wait:
                break

    def _recv_available(self) -> bytes:
        data = bytes()
        while self.shell.recv_ready():
            chunk = self.shell.recv(4096)
            if not chunk:
                break
            data += chunk
        return data

    def _select_recv(self) -> bytes | None:
        readable, _, _ = select.select([self.shell], [], [], 0.1)
        if readable and self.shell.recv_ready():
            new = self._recv_available()
            if new:
                return new
        return None

    def _decode_clean(self, raw_bytes: bytes) -> str:
        n = raw_bytes.count(b"\n") + 2
        screen = pyte.Screen(self._screen_width, n)
        stream = pyte.ByteStream(screen)
        stream.feed(raw_bytes)
        
        return "\n".join([
            line.rstrip()
            for line in screen.display
            if line.strip()
        ])

    def _strip_sentinel(self, text: str, sentinel: str) -> str:
        return text.replace(sentinel, '')

