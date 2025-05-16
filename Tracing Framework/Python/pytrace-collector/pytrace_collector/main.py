from typing import List
import os, sys, shutil, queue, time
import concurrent, concurrent.futures
from concurrent.futures import ThreadPoolExecutor, Future

from pytrace_collector.project import Generator
from pytrace_collector.trace.runner import Runner


class Collector:
    def __init__(
        self,
        work_dir: str,
        n_tot: int = -1,
        n_runners: int = 4,
        gen_type: str = "github",
    ) -> None:
        self.work_dir = work_dir
        self.proj_dir = os.path.join(work_dir, 'projs')
        self.n_tot = n_tot
        self.n_runners = n_runners
        self.gen_type = gen_type

        self.q: queue.Queue[str] = queue.Queue()


    def _proj_generator(self) -> None:
        with open(os.path.join(self.work_dir, 'gen.txt'), 'w') as log_file:
            for proj in Generator.make(
                gen_type=self.gen_type, save_dir=self.proj_dir, n_tot=self.n_tot,
                verbose=True, log_file=log_file,
            ):
                self.q.put(proj)


    def _proj_consumer(self, rank: int) -> None:
        tried_dir = os.path.join(self.work_dir, 'tried')
        os.makedirs(tried_dir, exist_ok=True)
        failed_dir = os.path.join(self.work_dir, 'failed')
        os.makedirs(failed_dir, exist_ok=True)
        while True:
            try:
                proj_path = self.q.get_nowait()
                runner = Runner(
                    work_dir=tried_dir, proj_path=proj_path, rank=rank,
                    verbose=True, shell_verbose=(self.n_runners == 1),
                )
                tried_proj_dir = runner.run_tests()
                if tried_proj_dir: # failed
                    failed_proj_dir = os.path.join(failed_dir, os.path.basename(tried_proj_dir))
                    if os.path.exists(failed_proj_dir):
                        shutil.rmtree(failed_proj_dir)                
                    shutil.move(tried_proj_dir, failed_proj_dir)
                    
            except queue.Empty:
                time.sleep(1)
    
    
    def collect(self) -> None:
        futs: List[Future] = []
        with ThreadPoolExecutor(1 + self.n_runners) as pool:
            
            futs.append(pool.submit(self._proj_generator))
            for r in range(self.n_runners):
                futs.append(pool.submit(self._proj_consumer, r))
            
            for fut in concurrent.futures.as_completed(futs):
                try:
                    _ = fut.result()
                except Exception as exc:
                    print(f'One thread raised an error: {exc}', file=sys.stderr, flush=True)
                    import traceback
                    traceback.print_exc()
                    


if __name__ == "__main__":
    
    gen_type = sys.argv[1] if len(sys.argv) > 1 else "github"
    if len(sys.argv) > 2:
        work_dir = sys.argv[2]
    else:
        from pytrace_collector.utils.logger import LOG_DIR
        work_dir = LOG_DIR


    collector = Collector(
        work_dir=work_dir,
        gen_type=gen_type,
        n_runners=4,
    )
    collector.collect()

