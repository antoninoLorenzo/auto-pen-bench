import re
import time
import uuid
import select

import chardet
import paramiko


# The original RemoteShell from APB had reliability issues and the output wasn't 
# cleaned properly from ASCII/OSC sequences (Kali returned OSC 3008).
# To reliably detect end of command a simple sentinel approach does it's job for 
# non-interactive commands.
class RemoteShell:

    def __init__(
        self, 
        shell: paramiko.Channel,
        timeout: float = 300.0
    ):
        self.shell = shell
        self.timeout = timeout
        shell_id = str(uuid.uuid4())
        self.sentinel = f"APB_shell_{shell_id}_END"
        self.in_sudo = False
        self.in_metasploit = False

        self._OSC_STRIP = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)')
        self._ANSI_STRIP = re.compile(
            r'\x1b\[[\x20-\x3f]*[\x40-\x7e]'  # CSI: covers ?2004h/l, ?1h, 4D, 4C, m, K...
            r'|\x1b[\x20-\x2f]*[\x30-\x7e]'   # other two-byte escapes: \x1b=, \x1b>, \x1b(B
        )
        self._MSF_PROMPT = re.compile(
            r'^msf(?:\d)?\s(?:(exploit|auxiliary|payload|post)\(.*\))?\s*>\s*$|^meterpreter\s>\s*$'
        )

    def _clean_output(self, command: str, raw: str) -> str:
        raw = raw.replace("\r", "")
        clean_output = self._ANSI_STRIP.sub('', self._OSC_STRIP.sub('', raw))
        
        # first line is echo
        idx = clean_output.find('\n')
        if idx >= 0:
            clean_output = clean_output[idx + 1:]
        
        return clean_output
    
    def _send_interrupt(self, interrupt_timeout: float = 1.0):
        sigint = b'\x03'
        self.shell.send(sigint)
        time.sleep(0.1)

        # flush output
        start_time = time.time()
        while True:
            if time.time() - start_time > interrupt_timeout:
                break

            readable, _, _ = select.select([self.shell], [], [], 0.1)
            if not readable:
                continue

            while self.shell.recv_ready():
                _ += self.shell.recv(4096)


    def execute_cmd(self, cmd: str) -> str:
        # to handle interactive commands within the benchmark (so sudo and metasploit) 
        # use special cases to break out of read loop.
        binary = cmd.split(' ')[0].strip()

        entering_sudo = not self.in_sudo and not self.in_metasploit and binary == 'sudo'
        sudo_response = self.in_sudo
        entering_msf = not self.in_sudo and not self.in_metasploit and binary == 'msfconsole'
        inside_msf = self.in_metasploit
        exiting_msf = inside_msf and cmd.strip() in ('exit', 'exit -y')

        if entering_sudo:
            self.in_sudo = True
            # sentinel is baked in here; it will fire once sudo completes and
            # control returns to the shell
            command_to_send = f"{cmd}; echo '{self.sentinel}'"
        elif sudo_response:
            # raw password only
            command_to_send = cmd
        elif entering_msf:
            self.in_metasploit = True
            command_to_send = cmd
        # exiting_msf must be evaluated before inside_msf
        elif exiting_msf:
            self.in_metasploit = False
            command_to_send = cmd
        elif inside_msf:
            command_to_send = cmd
        else:
            command_to_send = f"{cmd}; echo '{self.sentinel}'"

        # ensure the command is completely sent
        try:
            self.shell.sendall(f"{command_to_send}\n".encode())
            if exiting_msf:
                time.sleep(0.5)
                self.shell.sendall(f"echo '{self.sentinel}'\n".encode())
        except Exception as send_err:
            return str(send_err)

        raw_output = ""
        output_bytes = bytes()
        timed_out = False
        start_time = time.time()
        while True:
            if time.time() - start_time > self.timeout:
                timed_out = True
                break
            
            # select syscall on shell (Channel is waitable)  
            readable, _, _ = select.select([self.shell], [], [], 0.1)
            if not readable:
                continue
            
            # empty the buffer, original impl. called recv(9999) once and this 
            # resulted in uncomplete output.
            while self.shell.recv_ready():
                output_bytes += self.shell.recv(4096)

            try:
                raw_output = output_bytes.decode()
            except UnicodeDecodeError:
                encoding = chardet.detect(output_bytes)['encoding']
                raw_output = output_bytes.decode(encoding, errors='replace')
            
            cleaned = self._clean_output(command_to_send, raw_output)

            # MSF prompt detection: check the last non-empty line, not the full output
            if (entering_msf or inside_msf) and not exiting_msf:
                last_line = next((l for l in reversed(cleaned.split('\n')) if l.strip()), '')
                if self._MSF_PROMPT.match(last_line.strip()):
                    break
            elif entering_sudo:
                if '[sudo] password for' in cleaned:
                    break

            # sentinel-based termination (normal cmds, sudo response, msf exit)
            if self.sentinel in cleaned:
                if sudo_response:
                    self.in_sudo = False
                break
            
        command_result = self._clean_output(command_to_send, raw_output)
        # conceptually the sentinel could be replaced in `_clean_output`, however
        # doing so makes the break logic within the loop to never find the sentinel 
        # so keep it until we got out.
        command_result = command_result.replace(self.sentinel, '')
        if timed_out:
            command_result += '\nTimeout'
            self._send_interrupt()
            self.in_sudo = False
            self.in_metasploit = False
                
        return command_result
