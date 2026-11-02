import os
import importlib
from pathlib import Path

# Automatically import all model modules in this directory
models_path = Path(__file__).parent
for file in os.listdir(models_path):
    if file.endswith(".py") and file != "__init__.py":
        module_name = file[:-3]
        importlib.import_module(f"{__name__}.{module_name}")
