import os
import subprocess
from pathlib import Path

class Townname:
    def __init__(self):
        self.gimconv_path = Path('tools/GimConv')  # Path to GimConv directory
        self.output_folder = Path('2_translated/graphic/townname')  # Output directory for PNGs

    def convert_gim_to_png(self, input_folder: Path):
        """
        Converts all .gim files in the input folder to .png format and saves them
        in the output folder. Creates the output folder if it doesn't exist.
        """
        # Ensure the output folder exists
        self.output_folder.mkdir(parents=True, exist_ok=True)

        for root, _, files in os.walk(input_folder):
            for file in files:
                if file.endswith('.GIM'):
                    # Construct full paths
                    gim_file = Path(root) / file
                    png_file = self.output_folder / (Path(file).stem + '.png')

                    # Convert paths to be relative to the gimconv.exe location
                    relative_gim_file = os.path.relpath(gim_file, start=self.gimconv_path)
                    relative_png_file = os.path.relpath(png_file, start=self.gimconv_path)

                    # Execute the gimconv.exe tool
                    subprocess.run(
                        [str(self.gimconv_path / 'gimconv.exe'), relative_gim_file, '-o', relative_png_file],
                        cwd=self.gimconv_path
                    )
