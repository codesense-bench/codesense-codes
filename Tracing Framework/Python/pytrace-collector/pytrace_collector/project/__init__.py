from typing import Iterator
import abc, os, io

class Generator(abc.ABC):

    def __init__(
        self, save_dir: str, n_tot: int = -1,
        verbose: bool = True, log_file: io.TextIOWrapper | None = None,
    ) -> None:
        self.n_tot = n_tot
        self.n = 0
        self.save_dir = save_dir
        os.makedirs(save_dir, exist_ok=True)
        self.verbose = verbose
        self.log_file = log_file


    @abc.abstractmethod
    def __iter__(self) -> Iterator[str]:
        raise NotImplementedError
        while self.n_tot == -1 or self.n < self.n_tot:
            yield str(self.n)
            self.n += 1


    def _print(self, *args, **kwargs) -> None:
        if self.verbose:
            print(*args, **kwargs)


    @staticmethod
    def make(
        gen_type: str, save_dir: str, n_tot: int = -1,
        verbose: bool = True, log_file: io.TextIOWrapper | None = None,
    ):
        if gen_type == "github":
            from pytrace_collector.project.github import GitHubGenerator
            return GitHubGenerator(
                save_dir=save_dir, n_tot=n_tot, verbose=verbose, log_file=log_file,
            )
        elif gen_type == "local":
            from pytrace_collector.project.local import LocalGenerator
            return LocalGenerator(
                save_dir=save_dir, n_tot=n_tot, verbose=verbose, log_file=log_file,
            )
        else:
            raise ValueError(f"Unknown generator type: {gen_type}")
