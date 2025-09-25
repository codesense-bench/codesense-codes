import json
import inspect
import re
import pydoc
from importlib import import_module

COMMON_MODULES = [
    "os", "sys", "re", "json", "pathlib", "collections", "itertools", "functools",
    "datetime", "time", "math", "random", "statistics", "hashlib", "logging",
    "subprocess", "multiprocessing", "threading", "socket", "ssl", "urllib",
    "argparse", "configparser", "csv", "pickle", "sqlite3", "zipfile", "tarfile",
    

    "numpy", "pandas", "scipy", "statsmodels", "sympy",
    

    "torch", "tensorflow", "keras", "sklearn", "transformers",
    

    "matplotlib", "seaborn", "plotly", "bokeh",
    

    "requests", "flask", "django", "fastapi", "aiohttp", "bs4", "selenium",
    

    "sqlalchemy", "psycopg2", "pymongo", "redis",
    

    "unittest", "pytest", "mock",
    

    "typing", "enum", "pprint", "inspect", "pydoc", "glob", "shutil", "tempfile",
    

    "asyncio", "asyncpg", "aiofiles",

    "tkinter", "PyQt5", "wxPython",
    

    "platform", "getpass", "sysconfig", "distutils", "setuptools", "pip",
    

    "yaml", "xml", "lxml", "openpyxl", "PIL"  
]
for module in COMMON_MODULES:
    try:
        globals()[module] = import_module(module)
    except ImportError:
        pass

def extract_api_name(statement):
    """Extract the API name from a statement, ignoring variable assignments."""
    match = re.search(r"([a-zA-Z0-9_.]+)\(", statement)
    return match.group(1) if match else None

def get_api_description(api_name):
    """Fetch description of an API if available."""
    try:
        if '.' in api_name:
            parts = api_name.split('.')
            module_name = '.'.join(parts[:-1])
            func_name = parts[-1]
            module = import_module(module_name)
            func = getattr(module, func_name)
        else:
            func = eval(api_name)
            module = inspect.getmodule(func)
        
        doc = pydoc.getdoc(func)
        if doc:
            module_name = module.__name__ if module else "builtins"
            return f"Module: {module_name}\nDescription: {doc}"
    
    except (ImportError, AttributeError, NameError):
        pass
    
    return None

def get_api_code(api_name):
    """Fetch description and source code of an API if available."""
    try:
        # Case 1: Qualified name (module.function)
        if '.' in api_name:
            parts = api_name.split('.')
            module_name = '.'.join(parts[:-1])
            func_name = parts[-1]
            module = import_module(module_name)
            func = getattr(module, func_name)
        # Case 2: Standalone function
        else:
            func = eval(api_name)
            module = inspect.getmodule(func)
        
        doc = pydoc.getdoc(func)
        output = []
        
        if module:
            output.append(f"Module: {module.__name__}")

        # Try to get source code
        try:
            source = inspect.getsource(func)
            output.append(f"Module Source Code:\n{source}")
        except (TypeError, OSError):
            # Happens for C-extensions/builtins (no Python source)
            return None
        
        return "\n".join(output)
    
    except (ImportError, AttributeError, NameError):
        return None