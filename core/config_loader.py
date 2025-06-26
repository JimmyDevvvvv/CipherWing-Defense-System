# core/config_loader.py

import os
import yaml

def load_config():
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    path = os.path.join(base_dir, "config.yaml")
    with open(path, "r") as f:
        return yaml.safe_load(f)
