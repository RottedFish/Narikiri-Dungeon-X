from pathlib import Path
from .cab import extract_cab_file
from .pak import Pak
def extract_sys_cab(sys_data_path:Path):

    files = ['logo_all.bin', 'menutext.bin', 'title.bin']

    for file in sys_data_path.iterdir():
        if '.bin' in file.name:
            extract_cab_file(file, sys_data_path / f'cab_{file.stem}')

def get_extension(header:bytes):
    ext = '.pak'
    if header[0:3] == b'MIG':
        ext = '.gim'

    elif header == b'MSCF':
        ext = '.cab'

    elif header == b'TIM2':
        ext = '.tm2'

    return ext
def extract_lvl1(sys_data_path:Path):

    pak_files = ['menutex', 'title']

    for file in sys_data_path.iterdir():

        if file.stem in pak_files:
            extract_pak_files(sys_data_path / f'cab_{file.stem}' / f'{file.stem}.dat', 3)


def extract_pak_files(pak_file_path:Path, type:int):
    pak = Pak.from_path(pak_file_path, type)
    pak_folder = pak_file_path.parent / f'pak_{pak_file_path.stem}'
    pak_folder.mkdir(parents=True, exist_ok=True)

    for ind, pak_file in enumerate(pak.files):
        header = pak_file.data[0:4]
        ext = get_extension(header)

        with open(pak_folder / f'{ind}{ext}', 'wb') as f:
            f.write(pak_file.data)
def extract_lvl2(sys_data_path:Path):
    pak_files = ['menutex', 'title']

    for pak_file in pak_files:
        for file in (sys_data_path / f'cab_{pak_file}' / f'pak_{pak_file}').iterdir():

            if file.suffix == '.pak':
                extract_pak_files(file, 3)



