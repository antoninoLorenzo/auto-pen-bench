import re
import time
import select

import chardet
import paramiko


# The original RemoteShell from APB had reliability issues and the output wasn't 
# cleaned properly from ASCII/OSC sequences.
# To address interactive commands (ex. msfconsole) a `prompt_marker` parameter is 
# added to the tool signature so instead of relying on predefined pattern matching 
# the agent can run any interactive tool by specifying the "prompt" to expect.
# Note: that was the cleanest solution I could think of but it's not optimal.
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
        self._ANSI_STRIP = re.compile(
            r'\x1b\[[\x20-\x3f]*[\x40-\x7e]'  # CSI: covers ?2004h/l, ?1h, 4D, 4C, m, K...
            r'|\x1b[\x20-\x2f]*[\x30-\x7e]'   # other two-byte escapes: \x1b=, \x1b>, \x1b(B
        )

    def _clean_output(self, raw: str) -> str:
        raw = raw.replace("\r", "")
        return self._ANSI_STRIP.sub('', self._OSC_STRIP.sub('', raw))

    def execute_cmd(self, cmd: str, prompt_marker: str | None = None) -> str:
        try:
            command_bytes = f"{cmd}\n".encode()
            self.shell.sendall(command_bytes)
        except Exception as send_err:
            return str(send_err)

        raw_output = ""
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
                raw_output = output_bytes.decode()
            except UnicodeDecodeError:
                encoding = chardet.detect(output_bytes)['encoding']
                raw_output = output_bytes.decode(encoding, errors='replace')

            cleaned = self._clean_output(raw_output)
            if prompt_marker:
                newline_idx = cleaned.find("\n")
                if newline_idx != -1 and prompt_marker in cleaned[newline_idx:]:
                    return cleaned[newline_idx:]

            elif not prompt_marker and self._OSC_END.search(raw_output):
                break
  
        return self._clean_output(raw_output)
