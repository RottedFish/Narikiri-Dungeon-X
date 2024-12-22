import os
import shutil
from os import stat_result

import pandas as pd

from pathlib import Path
import pyjson5 as json
import pycdlib
import subprocess
import datetime
import lxml.etree as etree
from pythonlib.formats.FileIO import FileIO
from pythonlib.formats.fps4 import Fps4
from pythonlib.formats.tss import Tss
from pythonlib.formats.pak import Pak
from pythonlib.formats.text_toh import text_to_bytes, bytes_to_text
from pythonlib.formats.cab import extract_cab_file
import re
from itertools import chain
import io
from tqdm import tqdm
import struct



class ToolsNDX():


    def __init__(self, project_file: Path, insert_mask: list[str], changed_only: bool = False) -> None:
        os.environ["PATH"] += os.pathsep + os.path.join(os.getcwd(), 'pythonlib', '../utils')
        base_path = project_file.parent

        #if os.path.exists('programs_infos.json'):
        #    json_data = json.load(open('programs_infos.json'))
        #    self.desmume_path = Path(json_data['desmume_path'])
        #    self.save_size = json_data['save_size']

        self.jsonTblTags = {}
        self.ijsonTblTags = {}
        with open(project_file, encoding="utf-8") as f:
            json_raw = json.load(f)

        self.paths: dict[str, Path] = {k: base_path / v for k, v in json_raw["paths"].items()}
        self.main_exe_name = json_raw["main_exe_name"]
        self.asm_file = json_raw["asm_file"]

        json_raw = json.load(open(self.paths["encoding_table"], encoding="utf-8"))
        self.hashes = json.load(open(self.paths['hashes'], encoding="utf-8"))

        for k, v in json_raw.items():
            self.jsonTblTags[k] = {int(k2, 16): v2 for k2, v2 in v.items()}


        for k, v in self.jsonTblTags.items():
            if k in ['TAGS', 'TBL']:
                self.ijsonTblTags[k] = {v2:k2 for k2, v2 in v.items()}
            else:
                self.ijsonTblTags[k] = {v2: hex(k2).replace('0x', '').upper() for k2, v2 in v.items()}
        self.iTags = {v2.upper(): k2 for k2, v2 in self.jsonTblTags['TAGS'].items()}
        self.id = 1
        self.struct_id = 1

        # byteCode
        self.story_byte_code = b"\xF8"
        self.story_struct_byte_code = [b'\x0E\x10\x00\x0C\x04', b'\x00\x10\x00\x0C\x04']
        self.VALID_VOICEID = [r'(VSM_\w+)', r'(VCT_\w+)', r'(S\d+)', r'(C\d+)']
        self.list_status_insertion: list[str] = ['Done']
        self.list_status_insertion.extend(insert_mask)
        self.COMMON_TAG = r"(<[\w/]+:?\w+>)"
        self.changed_only = changed_only
        self.repo_path = str(base_path)
        self.file_dict = {
            "skit": "data/fc/fcscr",
            "story": "data/m"
        }

    def extract_iso(self, umd_iso: Path) -> None:

        print("Extracting ISO files...")
        iso = pycdlib.PyCdlib()
        iso.open(str(umd_iso))
        extract_to = self.paths["original_files"]
        self.clean_folder(extract_to)

        files = []
        for dirname, _, filelist in iso.walk(iso_path="/"):
            files += [dirname + "/" + x for x in filelist]

        for file in files:
            out_path = extract_to/ file[1:]
            out_path.parent.mkdir(parents=True, exist_ok=True)

            with iso.open_file_from_iso(iso_path=file) as f, open(str(out_path).split(";")[0], "wb+") as output:
                with tqdm(total=f.length(), desc=f"Extracting {file[1:].split(';')[0]}", unit="B", unit_divisor=1024,
                          unit_scale=True, leave=False) as pbar:
                    while data := f.read(2048):
                        output.write(data)
                        pbar.update(len(data))

        iso.close()
        #for element in self.paths['original_files'].iterdir():
        #    if (self.paths['original_files'] / element).is_dir():
        #        os.rename(self.paths['original_files'] / element, self.paths['original_files'] / "PSP_GAME")
        #    else:
        #        os.rename(self.paths['original_files'] / element), self.paths['original_files'] / "UMD_DATA.BIN")

    def make_iso(self, game_iso) -> None:
        #Clean old builds and create new one
        self.clean_builds(self.paths["game_builds"])

        # Set up new iso name and copy original iso in the folder

        n: datetime.datetime = datetime.datetime.now()
        new_iso = f"TalesofHearts_{n.year:02d}{n.month:02d}{n.day:02d}{n.hour:02d}{n.minute:02d}.nds"
        print(f'Making Iso {new_iso}...')
        self.new_iso = new_iso
        shutil.copy(game_iso, self.paths['game_builds'] / new_iso)

        path = self.folder_name / self.paths["final_files"]


    def patch_binaries(self):
        asm_path = self.paths["tools"] / "asm"

        env = os.environ.copy()
        env["PATH"] = f"{asm_path.as_posix()};{env['PATH']}"

        r = subprocess.run(
            [
                str(self.paths["tools"] / "asm" / "armips.exe"),
                str(self.paths["tools"] / "asm" / self.asm_file),
                "-strequ",
                "__OVERLAY3_PATH__",
                str(self.paths["temp_files"] / 'overlay' / 'overlay_0003.bin')
            ])
        if r.returncode != 0:
            raise ValueError("Error building code")

    def clean_folder(self, path: Path) -> None:
        target_files = list(path.iterdir())
        if len(target_files) != 0:
            print("Cleaning folder...")
            for file in target_files:
                if file.is_dir():
                    shutil.rmtree(file)
                elif file.name.lower() != ".gitignore":
                    file.unlink(missing_ok=False)

    def clean_builds(self, path: Path) -> None:
        target_files = sorted(list(path.glob("*.nds")), key=lambda x: x.name)[:-4]
        if len(target_files) != 0:
            print("Cleaning builds folder...")
            for file in target_files:
                print(f"Deleting {str(file.name)}...")
                file.unlink()

    def get_style_pointers(self, file: FileIO, ptr_range: tuple[int, int], base_offset: int, style: str) -> tuple[
        list[int], list[int]]:

        file.seek(ptr_range[0])
        pointers_offset: list[int] = []
        pointers_value: list[int] = []
        split: list[str] = [ele for ele in re.split(r'([PT])|(\d+)', style) if ele]

        while file.tell() < ptr_range[1]:
            for step in split:
                if step == "P":
                    off = file.read_uint32()
                    if base_offset != 0 and off == 0: continue

                    if (file.tell() - 4 < ptr_range[1]) and (off > base_offset):
                        pointers_offset.append(file.tell() - 4)
                        pointers_value.append(off - base_offset)
                elif step == "T":
                    off = file.tell()
                    pointers_offset.append(off)
                    pointers_value.append(off)
                else:
                    file.read(int(step))

        return pointers_offset, pointers_value

    def create_Node_XML(self, root, list_informations, section, entry_type:str, max_len = 0, ) -> None:
        strings_node = etree.SubElement(root, 'Strings')
        etree.SubElement(strings_node, 'Section').text = section

        for text, pointer_offset, emb in list_informations:
            self.create_entry(strings_node, pointer_offset, text, entry_type, -1, "")
            #self.create_entry(strings_node, pointers_offset, text, emb, max_len)

    def extract_all_menu(self, keep_translations=False) -> None:
        #xml_path = self.paths["menu_xml"]
        xml_path = self.paths["menu_original"]
        xml_path.mkdir(exist_ok=True)

        # Read json descriptor file
        with open(self.paths["menu_table"], encoding="utf-8") as f:
            menu_json = json.load(f)

        for entry in tqdm(menu_json, desc='Extracting Menu Files'):

            if entry["friendly_name"] == "Arm9" or entry["friendly_name"].startswith("Overlay"):
                file_path = self.paths["extracted_files"] / entry["file_path"]
            else:
                file_path = self.paths["original_files"] / entry["file_path"]

            with FileIO(file_path, "rb") as f:
                xml_data = self.extract_menu_file(entry, f, keep_translations)

            with open(xml_path / (entry["friendly_name"] + ".xml"), "wb") as xmlFile:
                xmlFile.write(xml_data)

            self.id = 1

    def extract_main_archive(self):
        order = {}
        order['order'] = []

        # Extract decrypted eboot
        self.extract_decripted_eboot()

        # Open the eboot and go at the start of the offsets table
        eboot = open(self.paths['extracted_eboot'] / self.main_exe_name, 'rb')
        eboot.seek(0x1FF624)

        print("Extract All.dat")
        with open(self.paths['original_all'], "rb") as all_read:
            while True:
                file_info = struct.unpack('<3I', eboot.read(12))
                if (file_info[2] == 0):
                    break
                hash_ = '%08X' % file_info[2]
                final_name = hash_
                if hash_ in self.hashes.keys():
                    final_name = self.hashes[hash_]

                self.extract_archive_file(file_info[0], file_info[1], final_name, all_read)
                order['order'].append(hash_)

            with open(self.paths['order'], 'w') as f:
                f.write(json.dumps(order, indent=4))


    def extract_archive_file(self, start:int, size:int, file_name:str, all_read):
        all_read.seek(start, 0)
        data = all_read.read(size)

        (self.paths['extracted_files'] / 'All' / file_name).parent.mkdir(parents=True, exist_ok=True)
        with open(self.paths['extracted_files'] / 'All' / file_name, mode='wb') as output_file:
            output_file.write(data)

    def extract_decripted_eboot(self):
        print("Extracting Eboot")
        original_eboot = self.paths['original_files'] / 'PSP_GAME' / 'SYSDIR' / self.main_exe_name
        self.paths['extracted_eboot'].mkdir(parents=True, exist_ok=True)
        dest_eboot = self.paths['extracted_eboot'] / self.main_exe_name

        args = ["deceboot.exe", str(original_eboot), str(dest_eboot)]
        #env["PATH"] = f"{env['PATH']}"

        listFile = subprocess.run(
            args,
            cwd= self.paths['utils'],
            shell=True,
            stdout=subprocess.DEVNULL
            )

    def extract_all_story(self, keep_translations=False):
        print("Extracting Story")
        cab_path = self.paths['extracted_files'] / 'All' / 'map' / 'pack'

        for cab_file in cab_path.iterdir():

            if 'ep_' in cab_file.name or 'sb_' in cab_file.name:
                extract_cab_file(cab_file, cab_path)
                self.extract_pak(cab_path / cab_file.stem / f'{cab_file.stem}.dat', 3)

    def extract_pak(self, file_path:Path, format:int):
        try:
            pak = Pak.from_path(file_path, format)

        except struct.error:
            print(f'Error with {file_path.stem}')

        else:
            for file in pak.files:

                if file.data[0:3] == b'TSS':
                    with open(file_path.parent / f'{file_path.stem}.tss', 'wb') as f:
                        f.write(file.data)
                    break


    def extract_menu_file(self, file_def, f: FileIO, keep_translations=False) -> bytes:

        base_offset = file_def["base_offset"]
        xml_root = etree.Element("MenuText")

        for section in file_def['sections']:
            max_len = 0
            pointers_offset  = []
            pointers_value = []
            if "pointers_start" in section.keys():
                pointers_start = int(section["pointers_start"])
                pointers_end = int(section["pointers_end"])

                # Extract Pointers list out of the file
                pointers_offset, pointers_value = self.get_style_pointers(f, (pointers_start, pointers_end), base_offset,
                                                                          section['style'])
            if 'pointers_alone' in section.keys():
                for ele in section['pointers_alone']:
                    f.seek(ele, 0)
                    pointers_offset.append(f.tell())
                    off = f.read_uint32() - base_offset
                    pointers_value.append(off)


            print(f"{section['section']} - Offset Min: {hex(min(pointers_value))} - Max: {hex(max(pointers_value))}")
            # Make a list, we also merge the emb pointers with the
            # other kind in the case they point to the same text
            temp = dict()
            for off, val in zip(pointers_offset, pointers_value):
                text, buff = bytes_to_text(f, val)
                temp.setdefault(text, dict()).setdefault("ptr", []).append(off)

            # Remove duplicates
            list_informations = [(k, str(v['ptr'])[1:-1], v.setdefault('emb', None)) for k, v in temp.items()]

            # Build the XML Structure with the information
            if 'style' in section.keys() and section['style'][0] == "T": max_len = int(section['style'][1:])
            self.create_Node_XML(xml_root, list_informations, section['section'], "String", max_len)

        if keep_translations:
            self.copy_translations_menu(root_original=xml_root, translated_path=self.paths['menu_xml'] / f"{file_def['friendly_name']}.xml")

        # Write to XML file
        return etree.tostring(xml_root, encoding="UTF-8", pretty_print=True)

    def parse_entry(self, xml_node):

        jap_text = xml_node.find('JapaneseText').text
        eng_text = xml_node.find('EnglishText').text
        status = xml_node.find('Status').text
        notes = xml_node.find('Notes').text

        final_text = eng_text or jap_text or ''
        return jap_text, eng_text, final_text, status, notes

    def copy_translations_menu(self, root_original, translated_path: Path):

        if translated_path.exists():

            original_entries = {entry_node.find('JapaneseText').text: (section.find('Section').text,) +
                                                                       self.parse_entry(entry_node) for section in
                                root_original.findall('Strings') for entry_node in section.findall('Entry')}

            tree = etree.parse(translated_path)
            root_translated = tree.getroot()
            translated_entries = {entry_node.find('JapaneseText').text: (section.find('Section').text,) +
                                                   self.parse_entry(entry_node) for section in
             root_translated.findall('Strings') for entry_node in section.findall('Entry')}


            for entry_node in root_original.iter('Entry'):

                jap_text = entry_node.find('JapaneseText').text

                if jap_text in translated_entries:

                    translated = translated_entries[jap_text]

                    if translated_entries[jap_text][2] is not None:
                        entry_node.find('EnglishText').text = translated_entries[jap_text][2]
                        entry_node.find('Status').text = translated_entries[jap_text][4]
                        entry_node.find('Notes').text = translated_entries[jap_text][5]

                else:
                    t = 2
                    #print(f'String: {jap_text} was not found in translated XML')

            #[print(f'{entry} was not found in original') for entry, value in translated_entries.items() if entry not in original_entries and entry is not None]

    def pack_all_menu(self) -> None:
        xml_path = self.paths["menu_xml"]

        # Read json descriptor file
        with open(self.paths["menu_table"], encoding="utf-8") as f:
            menu_json = json.load(f)

        for entry in tqdm(menu_json, total=len(menu_json), desc='Inserting Menu Files'):


            if entry["friendly_name"] in ['Arm9', 'Consumables', 'Sorma Skill', 'Outline', 'Overlay 0', 'Overlay 1', 'Overlay 3', 'Soma Data', 'Strategy', 'Battle Memo']:
                # Copy original files

                orig = self.paths["extracted_files"] / entry["file_path"]
                if not orig.exists():
                    orig = self.paths["original_files"] / entry["file_path"]

                dest = self.paths["temp_files"] / entry["file_path"]
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(orig, dest)

                base_offset = entry["base_offset"]
                pools: list[list[int]] = [[x[0], x[1] - x[0]] for x in entry["safe_areas"]]
                pools.sort(key=lambda x: x[1])

                with open(xml_path / (entry["friendly_name"] + ".xml"), "r", encoding='utf-8') as xmlFile:
                    root = etree.fromstring(xmlFile.read(), parser=etree.XMLParser(recover=True))

                with open(dest, "rb") as f:
                    file_b = f.read()

                with FileIO(file_b, "wb") as f:
                    self.pack_menu_file(root, pools, base_offset, f,entry['pad'])

                    f.seek(0)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with open(dest, "wb") as g:
                        g.write(f.read())

                #Copy in the patched folder
                if entry['friendly_name'] != "Arm9":
                    (self.paths['final_files'] / entry['file_path']).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(src=dest,
                                dst=self.paths['final_files'] / entry['file_path'])
                else:
                    shutil.copyfile(src=dest,
                                    dst=self.paths['final_files'] / 'arm9.bin')

    def pack_menu_file(self, root, pools: list[list[int]], base_offset: int, f: FileIO, pad=False) -> None:

        if root.find("Strings").find("Section").text == "Arm9":
            min_seq = 400
            entries = [ele for ele in root.iter("Entry") if
                       ele.find('PointerOffset').text not in ['732676', '732692', '732708']
                       and int(ele.find('Id').text) <= min_seq]
        else:
            entries = root.iter("Entry")

        line_counter = 0
        for line in entries:
            hi = []
            lo = []
            flat_ptrs = []

            p = line.find("EmbedOffset")
            if p is not None:
                hi = [int(x) - base_offset for x in p.find("hi").text.split(",")]
                lo = [int(x) - base_offset for x in p.find("lo").text.split(",")]

            poff = line.find("PointerOffset")
            if poff.text is not None:
                flat_ptrs = [int(x) for x in poff.text.split(",")]

            mlen = line.find("MaxLength")
            if mlen is not None:
                max_len = int(mlen.text)
                f.seek(flat_ptrs[0])
                text_bytes = self.get_node_bytes(line,pad) + b"\x00"
                if len(text_bytes) > max_len:
                    tqdm.write(
                        f"Line id {line.find('Id').text} ({line.find('JapaneseText').text}) too long, truncating...")
                    f.write(text_bytes[:max_len - 1] + b"\x00")
                else:
                    f.write(text_bytes + (b"\x00" * (max_len - len(text_bytes))))
                continue

            text_bytes = self.get_node_bytes(line,pad) + b"\x00"

            l = len(text_bytes)
            for pool in pools:

                if l <= pool[1]:
                    str_pos = pool[0]
                    #print(f'offset in pool: {hex(pool[0])}')
                    pool[0] += l;
                    pool[1] -= l

                    break
            else:
                print("Ran out of space")
                raise ValueError(f'Ran out of space in file: {root.find("Strings").find("Section").text} - line:{line_counter}')

            line_counter+= 1
            f.seek(str_pos)
            f.write(text_bytes)
            virt_pos = str_pos + base_offset
            for off in flat_ptrs:
                f.write_uint32_at(off, virt_pos)

            for _h, _l in zip(hi, lo):
                val_hi = (virt_pos >> 0x10) & 0xFFFF
                val_lo = (virt_pos) & 0xFFFF

                # can't encode the lui+addiu directly
                if val_lo >= 0x8000: val_hi += 1

                f.write_uint16_at(_h, val_hi)
                f.write_uint16_at(_l, val_lo)

    def get_node_bytes(self, entry_node, pad=False) -> bytes:

        # Grab the fields from the Entry in the XML
        #print(entry_node.find("JapaneseText").text)
        status = entry_node.find("Status").text
        japanese_text = entry_node.find("JapaneseText").text
        english_text = entry_node.find("EnglishText").text

        # Use the values only for Status = Done and use English if non-empty
        final_text = ''
        if (status in self.list_status_insertion):
            final_text = english_text or ''
        else:
            final_text = japanese_text or ''

        voiceid_node = entry_node.find("VoiceId")

        if voiceid_node is not None:
            final_text = f'<{voiceid_node.text}>' + final_text

        # Convert the text values to bytes using TBL, TAGS, COLORS, ...
        bytes_entry = text_to_bytes(final_text)

        # Pad with 00
        if pad:
            rest = 4 - len(bytes_entry) % 4 - 1
            bytes_entry += (b'\x00' * rest)

        return bytes_entry

    def create_entry(self, strings_node, pointer_offset, text, entry_type, speaker_id, unknown_pointer):

        # Add it to the XML node
        entry_node = etree.SubElement(strings_node, "Entry")
        etree.SubElement(entry_node, "PointerOffset").text = str(pointer_offset).replace(' ', '')
        text_split = re.split(self.COMMON_TAG, text)

        if len(text_split) > 1 and any(possible_value in text for possible_value in self.VALID_VOICEID):
            etree.SubElement(entry_node, "VoiceId").text = text_split[1]
            etree.SubElement(entry_node, "JapaneseText").text = ''.join(text_split[2:])
        else:
            etree.SubElement(entry_node, "JapaneseText").text = text

        etree.SubElement(entry_node, "EnglishText")
        etree.SubElement(entry_node, "Notes")

        if entry_type == "Struct":
            etree.SubElement(entry_node, "StructId").text = str(self.struct_id)
            etree.SubElement(entry_node, "SpeakerId").text = str(speaker_id)

        etree.SubElement(entry_node, "Id").text = str(self.id)
        etree.SubElement(entry_node, "Status").text = "To Do"
        self.id += 1

    def extract_from_string(self, f, strings_offset, pointer_offset, text_offset, root):

        f.seek(text_offset, 0)
        japText, buff = bytes_to_text(f, text_offset)
        self.create_entry(root, pointer_offset, japText, "Other Strings", -1, "")