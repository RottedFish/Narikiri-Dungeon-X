import os
import subprocess
from pathlib import Path

def convert_gim_to_png(input_folder: Path, output_folder: Path):
    gimconv_path = Path('tools/GimConv')  # Path to GimConv directory
    output_base_folder = Path(output_folder)  # take argument to be able to extract elsewhere

    """
    Converts all .gim and .tm2 files in the input folder (including nested folders) to .png format
    and saves them directly under the 2_translated/graphic/menutex folder without creating extra folders.
    """

    for root, _, files in os.walk(input_folder):
        # Calculate the relative path of the current folder with respect to the input folder
        relative_path = Path(root).relative_to(input_folder)

        # Define the corresponding output folder path
        # Use the output_base_folder directly without nesting additional folders
        output_folder = output_base_folder / relative_path

        # Ensure the output folder exists
        output_folder.mkdir(parents=True, exist_ok=True)

        for file in files:
            # Check for .gim and .tm2 files, case-insensitively
            if file.lower().endswith(('.gim', '.tm2')):
                # Construct full paths for the input and output files
                gim_file = Path(root) / file
                png_file = output_folder / (Path(file).stem + '.png')

                # Convert paths to be relative to the gimconv.exe location
                relative_gim_file = os.path.relpath(gim_file, start=gimconv_path)
                relative_png_file = os.path.relpath(png_file, start=gimconv_path)

                # Execute the gimconv.exe tool
                subprocess.run(
                    [str(gimconv_path / 'gimconv.exe'), relative_gim_file, '-o', relative_png_file],
                    cwd=gimconv_path
                )
