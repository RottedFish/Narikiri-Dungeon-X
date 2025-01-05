import struct
from pathlib import Path
from .FileIO import FileIO
from .fps4 import Fps4
from .text_ndx import bytes_to_text, text_to_bytes
import io
import lxml.etree as etree

class TalkData:

    def __init__(self, path:Path):
        self.fps4 = Fps4(header_path=path, detail_path=path)
        self.speaker_dict = {}
        self.speaker_id = 1
        self.id = 1
        self.root = etree.Element('SceneText')


    def extract_fps4(self, destination_path:Path, copy_path:Path):
        self.fps4.extract_files(destination_path=destination_path, copy_path=copy_path)

    def initialiaze(self):
        self.root = etree.Element('SceneText')
        speakers_node = etree.SubElement(self.root, 'Speakers')
        etree.SubElement(speakers_node, 'Section').text = "Speaker"
        story_node = etree.SubElement(self.root, 'Strings')
        etree.SubElement(story_node, 'Section').text = "Text"

        self.speaker_dict = {}
        self.speaker_id = 1
        self.id = 1

    def extract_all_talk(self, xml_path:Path):
        xml_path.mkdir(parents=True, exist_ok=True)

        for file in self.fps4.files:
            self.extract_talk(file.data, xml_path / f'{file.name.split(".")[0]}.xml')


    def extract_talk(self, data:bytes, xml_path:Path):
        self.initialiaze()
        entries = self.extract_information(data)
        self.write_speaker_nodes()
        self.write_entries(entries)

        txt = etree.tostring(self.root, encoding="UTF-8", pretty_print=True)
        with open(xml_path, "wb") as xmlFile:
            xmlFile.write(txt)

    def extract_information(self, data:bytes):
        entries = []
        struct_count = struct.unpack("<I", data[0:4])[0]
        start = 0x4

        file_buffer = FileIO(data)
        file_buffer.seek(start)
        pos = start

        for i in range(struct_count):
            # Extract Offsets
            pointer_offset = start + i*16
            file_buffer.seek(pointer_offset)
            unknown = file_buffer.read_uint32()
            voice_offset = file_buffer.read_uint32()
            speaker_offset = file_buffer.read_uint32()
            text_offset = file_buffer.read_uint32()

            # Extract values
            voice_id, _ = bytes_to_text(file_buffer, voice_offset)
            speaker, _ = bytes_to_text(file_buffer, speaker_offset)
            text, _ = bytes_to_text(file_buffer, text_offset)

            self.add_speaker_dict(speaker)
            entries.append((pointer_offset, voice_id, speaker, text))

        return entries
    def add_speaker_dict(self, speaker:str):

        if speaker not in self.speaker_dict.keys():
            self.speaker_dict[speaker] = self.speaker_id
            self.speaker_id += 1



    def write_speaker_nodes(self):
        speakers = self.root.find('Speakers')

        if speakers is not None:
            for speaker, speaker_id in self.speaker_dict.items():
                entry_node = etree.SubElement(speakers, "Entry")
                etree.SubElement(entry_node, "PointerOffset")
                etree.SubElement(entry_node, "JapaneseText").text = speaker
                etree.SubElement(entry_node, "EnglishText")
                etree.SubElement(entry_node, "Notes")
                etree.SubElement(entry_node, "Id").text = str(speaker_id)
                etree.SubElement(entry_node, "Status").text = 'To Do'


    def write_entries(self, entries:list):

        strings = self.root.find("Strings")

        for pointer_offset, voice_id, speaker, text in entries:
            entry_node = etree.SubElement(strings, "Entry")
            etree.SubElement(entry_node, "PointerOffset").text = str(pointer_offset)
            etree.SubElement(entry_node, "JapaneseText").text = text
            etree.SubElement(entry_node, "EnglishText")
            etree.SubElement(entry_node, "Notes")
            etree.SubElement(entry_node, "SpeakerId").text = str(self.speaker_dict[speaker])
            etree.SubElement(entry_node, "Id").text = str(self.id)
            etree.SubElement(entry_node, "Status").text = 'To Do'

            self.id += 1