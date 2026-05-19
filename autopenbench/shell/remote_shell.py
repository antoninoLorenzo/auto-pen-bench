import re
import time
import select

import chardet
import paramiko


# The original RemoteShell from APB had reliability issues and the output wasn't 
# cleaned properly from ASCII/OSC sequences.
# This implementation addresses those two issues, however it' completely non-interactive.
class RemoteShell:

    def __init__(
        self, 
        shell: paramiko.Channel,
        timeout: float = 300.0
    ):
        self.shell = shell
        self.timeout = timeout
        
        # While trying to implement a stop condition in the recv loop (since 
        # paramiko `exit_status_ready` doesn't work) I found out the raw output 
        # was composed by OSC 3008 sequences, they're actually a good way to 
        # avoid a PS1-based solution. That's actually unclear where exactly 
        # those come from.
        self._OSC_END = re.compile(r'\x1b\]3008;end=[^;]+;exit=(\w+)\x1b\\')
        self._OSC_STRIP = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)')
        self._ANSI_STRIP = re.compile(r'\x1b\[[0-9;]*[mKhl]|\x1b\(B|\x1b\[?\?[0-9]+[hl]')

    def _clean_output(self, raw: str) -> str:
        raw = raw.replace("\r", "")
        return self._ANSI_STRIP.sub('', self._OSC_STRIP.sub('', raw))

    def execute_cmd(self, cmd: str) -> str:
        try:
            command_bytes = f"{cmd}\n".encode()
            self.shell.sendall(command_bytes)
        except Exception as send_err:
            return str(send_err)

        output_bytes = bytes()
        start_time = time.time()
        while True:
            if time.time() - start_time > self.timeout:
                break

            readable, _, _ = select.select([self.shell], [], [], 0.1)
            if not readable:
                continue
            
            while self.shell.recv_ready():
                output_bytes += self.shell.recv(4096)

            try:
                raw = output_bytes.decode()
            except UnicodeDecodeError:
                encoding = chardet.detect(output_bytes)['encoding']
                raw = output_bytes.decode(encoding, errors='replace')

            end_match = self._OSC_END.search(raw)
            if end_match:
                break

        return self._clean_output(raw)
