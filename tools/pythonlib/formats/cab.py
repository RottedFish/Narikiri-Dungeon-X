import shutil
from dataclasses import dataclass
import struct
from .FileIO import FileIO
import os
from pathlib import Path
import subprocess


def extract_cab_file(file_path:Path, working_dir:Path):

    folder_cab_path = file_path.parent / file_path.stem
    folder_cab_path.mkdir(parents=True, exist_ok=True)
    subprocess.run(['expand', file_path, folder_cab_path / f'{file_path.stem}.dat'],
                   cwd=working_dir, stdout=subprocess.DEVNULL)


def make_cab_file(file_path):
    t = 2