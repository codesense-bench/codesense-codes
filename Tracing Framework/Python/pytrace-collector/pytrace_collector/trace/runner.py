from typing import List, Set, Tuple
import os, shutil, time, re

from pytrace_collector.utils.shell import Shell

RETRY_INSTALL_MODULE = 20
SET_PIP_CACHE_DIR = 'PIP_CACHE_DIR=/local/rcs/XXX/cache/pip TMPDIR=/local/rcs/XXX/tmp'
COLLECTOR_NAME = 'trace_collector.py'
CODE_COLLECTOR = '''# trace_collector.py
import runpy, os, signal
import pysnooper

def class_repr(obj):
    t_full = repr(type(obj))
    # <class 'name.to.match'>
    assert t_full.startswith("<class '") and t_full.endswith("'>"), t_full # TODO
    t = t_full[ len("<class '") : -len("'>") ]
    # https://docs.python.org/3/library/stdtypes.html#sequence-types-list-tuple-range
    if t in [
        'int', 'float', 'complex', 'bool', 'NoneType',
        'range', 'slice', 'memoryview',
    ]:
        return t
    elif t in [
        'list', 'tuple', 'set', 'dict', 'frozenset',
        'str', 'bytes', 'bytearray',
        'collections.deque', 'collections.OrderedDict',
    ]:
        return f'{t}<len={len(obj)}>'
    elif t  == 'torch.Tensor':
        shape = ','.join(str(s) for s in obj.shape)
        dtype = str(obj.dtype)[len('torch.'):]
        return f'{t}<dtype={dtype}, shape=({shape})>'
    elif t == 'numpy.ndarray':
        shape = ','.join(str(s) for s in obj.shape)
        dtype = str(obj.dtype)
        return f'{t}<dtype={dtype}, shape=({shape})>'
    return f'<class {t}>'

def is_obj_wo_repr(obj):
    return type(obj).__repr__ is object.__repr__

def expand_obj(obj):
    selected_kv = {}
    for k, v in obj.__dict__.items():
        vrepr = repr(v)
        if (
            any(vrepr.startswith(p) for p in [
                '<function', '<module', '<class', '<enum', '<_frozen',
                '<bound method', '<method',
            ]) and vrepr.endswith('>')
        ):
            continue
        selected_kv[k] = vrepr
    # end for
    return f'{{{", ".join(f"{k}={v}" for k, v in selected_kv.items())}}}'

tracer = pysnooper.snoop(
    'trace_pytest.log', depth=1024,
    relative_time=False, max_variable_length=8192,
    source_paths='SRC_PATHS',
    exclude_paths=__file__,
    save_framed_traces='FRAME_SAVE_PATH/collected_traces.json',
    watch_explode=('self'),
    custom_repr=(
        (is_obj_wo_repr, expand_obj),
    ),
    custom_class_repr=class_repr,
)

def exit_tracer(signum, frame):
    if not tracer.exited:
        tracer.__exit__(None, None, None)
    exit(0)

signal.signal(signal.SIGTERM, exit_tracer)

tracer.__enter__()
try:
    ret = runpy.run_module(
        mod_name='pytest',
        run_name='__main__',
        alter_sys=True,
    )
except SystemExit:
    pass

exit_tracer(None, None)
'''

def pkg_map(p: str) -> str:
    return {
        'yaml': 'pyyaml',
        'dateutil': 'python-dateutil',
    }.get(p, p)


class Runner:

    def __init__(
        self,
        work_dir: str,
        proj_path: str,
        rank: int,
        verbose: bool = True,
        shell_verbose: bool = False,
    ) -> None:
        self.rank = rank
        os.makedirs(work_dir, exist_ok=True)
        self.proj_name = os.path.basename(proj_path)
        
        self.work_dir = os.path.abspath(os.path.join(work_dir, self.proj_name))
        os.makedirs(self.work_dir, exist_ok=False)

        self.proj_path = os.path.abspath(os.path.join(self.work_dir, self.proj_name))
        if os.path.exists(self.proj_path):
            shutil.rmtree(self.proj_path)
        assert os.path.exists(proj_path)
        shutil.copytree(proj_path, self.proj_path, symlinks=True)
        
        self.collector_path = os.path.join(self.work_dir, COLLECTOR_NAME)
        with open(self.collector_path, 'w') as f:
            f.write(CODE_COLLECTOR
                    .replace('SRC_PATHS', self.proj_path)
                    .replace('FRAME_SAVE_PATH', self.work_dir)
            )
        self.run_collector_cmd = f'python {self.collector_path} {self.proj_path} -s'

        self.verbose = verbose
        self.shell_verbose = shell_verbose
        self.log_file = open(os.path.join(self.work_dir, 'run.log'), 'w')
        self.shell = Shell(print_out=self.shell_verbose, print_file=self.log_file)


    def _print(self, *args, **kwargs) -> None:
        print(*args, **kwargs, file=self.log_file)
        if self.verbose:
            print(f'[runner {self.rank}] ', end='', flush=True)
            print(*args, **kwargs)
    

    def cdbash(self, cmd: str, timeout: float|None = None) -> Tuple[str, str, int]:
        return self.shell.bash(f'cd {self.proj_path} && {cmd}', timeout)


    def run_tests(self,) -> str | None:
        # run
        self._print(f'try {self.proj_name}', flush=True)
        start_time = time.time()
        for run_func in [self._mamba_run]:
            if run_func():
                self._print(f'successfully tried {self.proj_name} with {run_func.__name__}', flush=True)
                break
        else:
            self._print(f'fail to try {self.proj_name}', flush=True)
        
        # check
        ret: str | None = self.work_dir
        collected_traces_path = os.path.join(self.work_dir, 'collected_traces.json')
        if os.path.exists(collected_traces_path):
            with open(collected_traces_path, 'r') as f:
                first_line = f.readline().strip()
            if first_line != '{}':
                ret = None
        
        if not ret:
            self._print(f'collected for {self.proj_name}', flush=True, end='')
        else:
            self._print(f'failed to collect for {self.proj_name}', flush=True, end='')
        dur_min = (time.time() - start_time) / 60
        self._print(f'    in {dur_min:.1f} mins', flush=True)

        return ret


    def _poetry_run(self,) -> bool:
        raise NotImplementedError
        # condition
        toml_file = os.path.join(self.proj_path, 'pyproject.toml')
        if not os.path.exists(toml_file):
            return False
        with open(toml_file, 'r') as f:
            if 'tool.poetry' not in f.read():
                return False
        
        # deps
        self.shell.bash(r'echo -e "\n======== try poetry ========\n\n"')
        self.cdbash('poetry install -n', timeout=8*60)
        self.cdbash(f'{SET_PIP_CACHE_DIR} poetry run -- pip install --no-input pytest pytest-cov', timeout=2*60)
        self.cdbash(f'cd /home/XXX/code/PySnooper && poetry run -- python setup.py install')

        # run
        for _ in range(RETRY_INSTALL_MODULE):
            out, err, _ = self.cdbash(f'export PYTHONPATH=$PYTHONPATH:{self.proj_path} && poetry run -- {self.run_collector_cmd}', timeout=15*60)
            res: re.Match = re.search(r"No module named '(.*?)'", '\n\n'.join([out, err]))
            if res:
                m404 = pkg_map(res.group(1))
                if self.cdbash(f'{SET_PIP_CACHE_DIR} poetry run -- pip install --no-input {m404}', timeout=2*60)[2] != 0:
                    break
            else:
                break
        
        # clean
        python_path = self.cdbash('poetry run -- which python')[0].strip()
        self.shell.bash(f'poetry env remove {python_path}')

        self.shell.bash(r'echo -e "\n======== end poetry ========\n\n"')

        return True
        

    def _mamba_run(self,) -> bool:
        self.shell.bash(r'echo -e "\n======== try mamba ========\n\n"')
        # condition
        env_yml_file = None
        for f in os.listdir(self.proj_path):
            if os.path.isfile(f) and re.match(r'environment.*\.yml', f):
                env_yml_file = os.path.join(self.proj_path, f)
                break
        
        if env_yml_file:
            self.shell.bash(f'mamba env create -y -f {env_yml_file} -n {self.proj_name}', timeout=8*60)
        else:
            self.shell.bash(f'mamba create -y -n {self.proj_name} python=3.9', timeout=8*60)
        
        _mamba_prefix = os.environ['CONDA_PREFIX']
        if '/envs' in _mamba_prefix:
            _mamba_prefix = _mamba_prefix.split('/envs')[0]
        
        def mamba_run(cmd: str, timeout: float|None = None) -> Tuple[str, str, int]:
            return self.shell.bash(f'source {_mamba_prefix}/bin/activate {self.proj_name} && {cmd}', timeout=timeout)
        
        def mamba_cdrun(cmd: str, timeout: float|None = None) -> Tuple[str, str, int]:
            return self.cdbash(f'source {_mamba_prefix}/bin/activate {self.proj_name} && {cmd}', timeout=timeout)

        # deps
        # deps by poetry
        toml_file = os.path.join(self.proj_path, 'pyproject.toml')
        if os.path.exists(toml_file):
            with open(toml_file, 'r') as f:
                if 'tool.poetry' in f.read():
                    self.shell.bash(r'echo -e "\n==== try poetry inside mamba ====\n\n"')
                    mamba_cdrun(f'poetry install -n')
        # deps by requirement files
        req_files: Set[str] = set()
        req_dir_pattern = re.compile(r'.*requirement.*')
        req_file_pattern = re.compile(r'requirement.*\.txt$|test(-|_)requirement.*\.txt$')
        for root, dirs, files in os.walk(self.proj_path):
            assert os.path.isabs(root)
            for f in files:
                if req_file_pattern.match(f):
                    req_files.add(os.path.join(root, f))
                else:
                    parent_dir = os.path.basename(root)
                    if req_dir_pattern.match(parent_dir):
                        req_files.add(os.path.join(root, f))
        # end for
        for req_file in req_files:
            mamba_run(f'which pip && {SET_PIP_CACHE_DIR} pip install --no-input -r {req_file}', timeout=8*60)
        # other fixed deps
        mamba_run(f'{SET_PIP_CACHE_DIR} pip install --no-input pytest pytest-cov', timeout=2*60)
        mamba_run(f'cd /home/XXX/code/PySnooper && python setup.py install', timeout=2*60)
        mamba_cdrun(f'mamba env export -n {self.proj_name} > ../env.yml', timeout=2*60)

        # run
        for _ in range(RETRY_INSTALL_MODULE):
            out, err, _ = mamba_cdrun(f'export PYTHONPATH=$PYTHONPATH:{self.proj_path} && {self.run_collector_cmd}', timeout=15*60)
            res: re.Match = re.search(r"No module named '(.*?)'", '\n\n'.join([out, err]))
            if res:
                m404 = pkg_map(res.group(1).split('.')[0])
                if mamba_run(f'{SET_PIP_CACHE_DIR} pip install --no-input {m404}', timeout=2*60)[2] != 0:
                    break
            else:
                break
        
        # clean
        self.shell.bash(f'mamba env remove -y -n {self.proj_name}')
        self.shell.bash(r'echo -e "\n======== end mamba ========\n\n"')

        return True

