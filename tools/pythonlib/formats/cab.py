import shutil
from dataclasses import dataclass
import struct
from .FileIO import FileIO
import os
from pathlib import Path
import subprocess


def extract_cab_file(cab_file_path:Path, folder_path:Path):

    folder_path.mkdir(parents=True, exist_ok=True)
    subprocess.run(['expand', cab_file_path, folder_path / f'{cab_file_path.stem}.dat'],
                 stdout=subprocess.DEVNULL)


def make_cab_file(file_path):
    t = 2