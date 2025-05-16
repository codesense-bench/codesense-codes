from typing import Iterator, cast
import os, datetime, io
import github, github.Repository, github.ContentFile

from pytrace_collector.project import Generator
from pytrace_collector.utils.shell import Shell

from IPython import embed

class GitHubGenerator(Generator):
    def __init__(
        self, save_dir: str, n_tot: int = -1,
        verbose: bool = True, log_file: io.TextIOWrapper | None = None,
    ) -> None:
        super().__init__(save_dir=save_dir, n_tot=n_tot, verbose=verbose, log_file=log_file)
        auth = github.Auth.Login("Co1lin", "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")
        self.gh = github.Github(auth=auth)
        self.gh.get_user().login
        self.shell = Shell(print_out=self.verbose, print_file=self.log_file)


    def __iter__(self) -> Iterator[str]:
        repo_iter = iter(self.gh.search_repositories(
            query='language:python',
            sort='stars',
            order='desc',
        ))
        while self.n_tot == -1 or self.n < self.n_tot:
            repo = next(repo_iter)
            
            if '+' in repo.full_name:
                embed()

            clone_name = repo.full_name.replace("/", "+")
            clone_dir = os.path.join(self.save_dir, clone_name)
            if os.path.exists(clone_dir):
                continue
            
            if not self._filter_criteria(repo):
                continue
            
            self.n += 1
            
            self._print(f'\n========  [{self.n}/{self.n_tot}]  {repo.clone_url}', flush=True)
            self.shell.run(f'git clone {repo.clone_url} {clone_dir}')
            print()
            
            yield clone_dir


    def _filter_criteria(self, repo: github.Repository.Repository) -> bool:

        def has_tests(repo: github.Repository.Repository) -> bool:
            test_dir_cands = ['test', 'tests', 'testing', 'testings']
            is_candidate = lambda d: d.name.lower() in test_dir_cands
            for d0 in repo.get_contents('.'):
                d0 = cast(github.ContentFile.ContentFile, d0)
                if d0.type == 'dir':
                    if is_candidate(d0):
                        return True
                    for d1 in repo.get_contents(d0.path):
                        d1 = cast(github.ContentFile.ContentFile, d1)
                        if d1.type == 'dir' and is_candidate(d1):
                            return True

        def recently_updated(repo: github.Repository.Repository) -> bool:
            return (datetime.datetime.now(datetime.timezone.utc) - repo.updated_at).days <= 365*4

        return has_tests(repo) and recently_updated(repo)

