from typing import Iterator, cast
import os, io
from natsort import natsorted

from pytrace_collector.project import Generator


class LocalGenerator(Generator):
    def __init__(
        self, save_dir: str, n_tot: int = -1,
        verbose: bool = True, log_file: io.TextIOWrapper | None = None,
    ) -> None:
        super().__init__(save_dir=save_dir, n_tot=n_tot, verbose=verbose, log_file=log_file)
        

    def __iter__(self) -> Iterator[str]:
        for proj in natsorted(os.listdir(self.save_dir)):
            clone_dir = os.path.join(self.save_dir, proj)
            if os.path.isdir(clone_dir):
                self._print(f'\n========  [{self.n}/{self.n_tot}]  {clone_dir}', flush=True)
                yield clone_dir
                
                self.n += 1
                if self.n_tot != -1 and self.n >= self.n_tot:
                    break
