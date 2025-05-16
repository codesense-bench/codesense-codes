# https://stackoverflow.com/a/57084403
from typing import List, Tuple
import sys, io, queue, psutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

    
class Shell:
    def __init__(
        self,
        shell_exec: bool = True,
        print_out: bool = True,
        print_cmd: bool = True,
        print_file: io.TextIOWrapper | None = None,
        return_list: bool = False,
    ) -> None:
        self.shell_exec = shell_exec
        self.print_out = print_out
        self.print_cmd = print_cmd
        self.print_file = print_file
        self.return_list = return_list


    def _read_popen_pipes(self, p: subprocess.Popen, timeout_sec: float|None = None):

        def _enqueue_output(file: io.TextIOWrapper, q: queue.Queue):
            for line in iter(file.readline, ''):
                q.put(line)
            file.close()

        def _timeout():
            try:
                p.wait(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                parent = psutil.Process(p.pid)
                for child in parent.children(recursive=True):
                    child.terminate()
                parent.terminate()

        with ThreadPoolExecutor(3) as pool:
            q_stdout, q_stderr = queue.Queue(), queue.Queue()

            if timeout_sec is not None:
                pool.submit(_timeout)
            pool.submit(_enqueue_output, p.stdout, q_stdout)
            pool.submit(_enqueue_output, p.stderr, q_stderr)

            while p.poll() is None or not q_stdout.empty() or not q_stderr.empty():
                out_line = err_line = ''

                try:
                    out_line = q_stdout.get_nowait()
                except queue.Empty:
                    pass

                try:
                    err_line = q_stderr.get_nowait()
                except queue.Empty:
                    pass

                yield (out_line, err_line)
    

    def run(self, cmd: str | List[str], timeout: float|None = None) -> Tuple[str|List[str], str|List[str], int]:
        with subprocess.Popen(
            cmd, shell=self.shell_exec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ) as p:
            if self.print_cmd:
                if self.print_out:
                    print(f'+ {cmd}', file=sys.stderr, flush=True)
                if self.print_file:
                    print(f'+ {cmd}', file=self.print_file, flush=True)
            out: List[str] = []
            err: List[str] = []
            for out_line, err_line in self._read_popen_pipes(p, timeout):
                out.append(out_line)
                err.append(err_line)
                if self.print_out:
                    print(out_line, end='', flush=True)
                    print(err_line, end='', file=sys.stderr, flush=True)
                if self.print_file:
                    print(out_line, end='', flush=True, file=self.print_file)
                    print(err_line, end='', flush=True, file=self.print_file)
            # end for
            if self.return_list:
                return out, err, p.returncode
            else:
                return ''.join(out), ''.join(err), p.returncode
    

    def bash(self, cmd: str, timeout: float|None = None) -> Tuple[str, str, int]:
        _prev_shell_exec = self.shell_exec
        self.shell_exec = True
        assert "'" not in cmd, f'cmd should not contain single quote: {cmd}'
        ret = self.run(f'bash -c \'{cmd}\'', timeout)
        self.shell_exec = _prev_shell_exec
        return ret


if __name__ == '__main__':
    Shell().run('''echo '#!/bin/bash

for i in {1..10}
do
    echo "Sleep $i to stdout" >> /dev/stdout
    echo "Sleep $i to stderr" >> /dev/stderr
    sleep 1
done
' > sleep.sh && chmod +x sleep.sh''')

    out, err, code = Shell().run('./sleep.sh', timeout=2)
    print(f'{out = }')
    print(f'{err = }')
    print(f'{code = }')

    Shell().run('rm sleep.sh')
