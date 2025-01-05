import struct
from pathlib import Path
from .FileIO import FileIO
from .fps4 import Fps4
from .text_ndx import bytes_to_text, text_to_bytes
import io
import lxml.etree as etree

class CharacterData:

    def __init__(self, path:Path):
        self.fps4 = Fps4(header_path=path, detail_path=path)
        self.id = 1
        self.root = etree.Element('MenuText')


    def extract_fps4(self, destination_path:Path, copy_path:Path):
        self.fps4.extract_files(destination_path=destination_path, copy_path=copy_path)

    def initialiaze(self):
        self.root = etree.Element('MenuText')
        story_node = etree.SubElement(self.root, 'Strings')
        etree.SubElement(story_node, 'Section').text = "Text"

        self.id = 1

    def extract_all_character(self, xml_path:Path):
        xml_path.mkdir(parents=True, exist_ok=True)

        for file in self.fps4.files:
            self.extract_character(file.data, xml_path / f'{file.name.split(".")[0]}.xml')


    def extract_character(self, data:bytes, xml_path:Path):
        self.initialiaze()
        entries = self.extract_information(data)
        self.write_entries(entries)

        txt = etree.tostring(self.root, encoding="UTF-8", pretty_print=True)
        with open(xml_path, "wb") as xmlFile:
            xmlFile.write(txt)

    def extract_information(self, data: bytes):
        """
        Extract the 3 fixed entries based on pointer offsets from binary data.
        """
        entries = []
        start = 0x4
        pointer_size = 4  # Each pointer is 4 bytes
        file_buffer = FileIO(data)

        for i in range(3):  # Always process exactly 3 pointers
            pointer_offset = start + i * pointer_size
            file_buffer.seek(pointer_offset)

            # Read pointer and text
            try:
                text_offset = file_buffer.read_uint32()
                text, _ = bytes_to_text(file_buffer, text_offset)
            except Exception as e:
                raise ValueError(f"Error processing pointer at offset {pointer_offset}: {e}")

            entries.append((pointer_offset, text))

        return entries


    def write_entries(self, entries:list):

        strings = self.root.find("Strings")

        for pointer_offset, text in entries:
            entry_node = etree.SubElement(strings, "Entry")
            etree.SubElement(entry_node, "PointerOffset").text = str(pointer_offset)
            etree.SubElement(entry_node, "JapaneseText").text = text
            etree.SubElement(entry_node, "EnglishText")
            etree.SubElement(entry_node, "Notes")
            etree.SubElement(entry_node, "Id").text = str(self.id)
            etree.SubElement(entry_node, "Status").text = 'To Do'

            self.id += 1