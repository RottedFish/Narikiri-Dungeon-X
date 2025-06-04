import argparse
from pathlib import Path

from pythonlib.games.ToolsNDX import ToolsNDX

SCRIPT_VERSION = "0.0.3"

def get_arguments(argv=None):
    # Init argument parser
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-p",
        "--project",
        required=True,
        type=Path,
        metavar="project",
        help="project.json file path",
    )

    sp = parser.add_subparsers(title="Available actions", required=False, dest="action")

    # Extract commands
    sp_extract = sp.add_parser(
        "extract",
        description="Extract the content of the files",
        help="Extract the content of the files",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    sp_extract.add_argument(
        "-ft",
        "--file_type",
        choices=["Iso", "Menu", "Story", "Skits", "Map", "Graphic", "All"],
        required=True,
        metavar="file_type",
        help="(Required) - Options: Iso, Menu, Story, Skits, Map, Graphic, All",
    )

    sp_extract.add_argument(
        "-i",
        "--iso",
        required=False,
        type=Path,
        default="../b-topndxj.iso",
        metavar="iso",
        help="(Optional) - Only for extract Iso command",
    )

    sp_extract.add_argument(
        "-r",
        "--replace",
        required=False,
        metavar="replace",
        default=False,
        help="(Optional) - Boolean to uses translations from the Repo to overwrite the one in the Data folder",
    )

    sp_extract.add_argument(
        "--only-changed",
        required=False,
        action="store_true",
        help="(Optional) - Insert only changed files not yet commited",
    )

    sp_insert = sp.add_parser(
        "insert",
        help="Take the new texts and recreate the files",
    )

    sp_insert.add_argument(
        "-ft",
        "--file_type",
        choices=["Iso", "Main", "Menu", "Story", "Skits", "Map", "Graphic", "All", "Asm"],
        required=True,
        metavar="file_type",
        help="(Required) - Options: Iso, Init, Main, Elf, Story, Skits, Map, Graphic, All, Asm",
    )

    sp_insert.add_argument(
        "-i",
        "--iso",
        required=False,
        type=Path,
        default="",
        metavar="iso",
        help="(Required) - Can be relative path to the Repo folder",
    )

    sp_insert.add_argument(
        "--with-proofreading",
        required=False,
        action="store_const",
        const="Proofreading",
        default="",
        help="(Optional) - Insert lines in 'Proofreading' status",
    )

    sp_insert.add_argument(
        "--with-editing",
        required=False,
        action="store_const",
        const="Editing",
        default="",
        help="(Optional) - Insert lines in 'Editing' status",
    )

    sp_insert.add_argument(
        "--with-problematic",
        required=False,
        action="store_const",
        const="Problematic",
        default="",
        help="(Optional) - Insert lines in 'Problematic' status",
    )

    sp_insert.add_argument(
        "--only-changed",
        required=False,
        action="store_true",
        help="(Optional) - Insert only changed files not yet commited",
    )

    args = parser.parse_args()

    return args

if __name__ == "__main__":

    args = get_arguments()

    insert_mask = []
    if args.action == "insert":
        insert_mask = [
            args.with_proofreading,
            args.with_editing,
            args.with_problematic,
        ]

    tales_instance = ToolsNDX(
        args.project.resolve(), insert_mask, args.only_changed
    )

    if args.action == "insert":

        if args.file_type == "Menu":
            tales_instance.pack_all_menu()
            tales_instance.make_iso(Path(args.iso))

        if args.file_type == "Iso":
            tales_instance.make_iso(args.iso.resolve())

        elif args.file_type == "Skits":
            tales_instance.pack_all_skits()

        elif args.file_type == "Story":
            tales_instance.pack_all_story_sb()

        elif args.file_type == "All":
            print(args.iso.resolve())
            tales_instance.pack_menu_bg()
            tales_instance.pack_all_skits()
            tales_instance.pack_all_story()
            tales_instance.pack_all_menu()
            tales_instance.patch_binaries()


    if args.action == "extract":

        if args.file_type == "Menu":
            tales_instance.extract_archives()
            tales_instance.extract_all_menu(args.replace)

        elif args.file_type == "Iso":
            tales_instance.extract_iso(Path(args.iso.resolve()))
            tales_instance.extract_main_archive()

        elif args.file_type == "Skits":
            tales_instance.extract_all_skits(keep_translations=True)

        elif args.file_type == "Story":
            tales_instance.extract_all_story_sb(keep_translations=True)
            
        elif args.file_type == "Map":
            tales_instance.extract_all_map(args.replace)
            
        elif args.file_type == "Graphic":
            tales_instance.extract_townname()
            tales_instance.extract_all_sysdata()

        elif args.file_type == "All":
            tales_instance.extract_iso(Path(args.iso.resolve()))
            tales_instance.extract_main_archive()
            #tales_instance.extract_all_map(args.replace)
            #tales_instance.extract_all_sysdata()
            tales_instance.extract_field()
            tales_instance.extract_all_story_sb(args.replace)
            tales_instance.extract_archives()
            tales_instance.extract_all_menu(args.replace)