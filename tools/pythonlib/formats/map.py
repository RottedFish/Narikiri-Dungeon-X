import os
import struct
from pathlib import Path

def extract_tss_from_map(map_file_path:Path):

    size = os.path.getsize(map_file_path)
    with open(map_file_path, 'rb') as map:
        map.seek(0x6C)
        tss_offset = struct.unpack('<I', map.read(4))[0]

        map.seek(tss_offset)
        tss_data = map.read(size - tss_offset)
        with open(map_file_path.parent / f'{map_file_path.stem}.tss', 'wb') as tss:
            tss.write(tss_data)

