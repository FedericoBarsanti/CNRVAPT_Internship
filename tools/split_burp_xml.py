#!/usr/bin/env python3
"""
Reusable Burp Suite XML Splitter
Splits large Burp HTTP history XML files into manageable AI-readable parts.

Usage:
    python3 split_burp_xml.py <input_xml> [--items-per-part N] [--output-dir DIR]

Examples:
    # Split with default 50 items per part
    python3 split_burp_xml.py 01-burp/client_signin.xml

    # Customize items per part
    python3 split_burp_xml.py 01-burp/client_signin.xml --items-per-part 100

    # Specify output directory
    python3 split_burp_xml.py 01-burp/client_signin.xml --output-dir 01-burp/xml_subdivision
"""

import xml.etree.ElementTree as ET
import sys
import argparse
from pathlib import Path


def split_burp_xml(input_file, output_dir, items_per_part=50):
    """
    Split Burp Suite XML file into parts with specified number of items each.

    Args:
        input_file: Path to input Burp XML file
        output_dir: Directory to save split files
        items_per_part: Number of <item> elements per output file

    Returns:
        List of created file paths
    """
    input_path = Path(input_file)
    output_path = Path(output_dir)

    # Validate input file exists
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")

    # Create output directory if needed
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"[*] Parsing XML file: {input_file}")
    tree = ET.parse(input_file)
    root = tree.getroot()

    # Get all item elements
    items = root.findall('item')
    total_items = len(items)

    print(f"[+] Found {total_items} items in {input_file}")

    # Calculate number of parts needed
    num_parts = (total_items + items_per_part - 1) // items_per_part
    print(f"[+] Will create {num_parts} parts with ~{items_per_part} items each")

    # Generate base filename from input
    base_name = input_path.stem  # filename without extension

    created_files = []
    for part_num in range(num_parts):
        # Create new XML document for this part
        new_root = ET.Element('items')

        # Copy attributes from original root if present
        for attr_name, attr_value in root.attrib.items():
            new_root.set(attr_name, attr_value)

        # Calculate item range for this part
        start_idx = part_num * items_per_part
        end_idx = min(start_idx + items_per_part, total_items)

        # Add items to new document
        for i in range(start_idx, end_idx):
            new_root.append(items[i])

        # Create output filename with zero-padded part number
        output_file = output_path / f"{base_name}_part{part_num + 1:02d}.xml"

        # Write XML file with proper formatting
        new_tree = ET.ElementTree(new_root)
        ET.indent(new_tree, space="  ")
        new_tree.write(output_file, encoding='utf-8', xml_declaration=True)

        print(f"[+] Created {output_file.name} with items {start_idx + 1}-{end_idx}")
        created_files.append(str(output_file))

    print(f"\n[✓] Successfully created {len(created_files)} files in {output_dir}")
    return created_files


def main():
    parser = argparse.ArgumentParser(
        description='Split large Burp Suite XML files into AI-readable parts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument(
        'input_file',
        help='Path to input Burp Suite XML file'
    )

    parser.add_argument(
        '--items-per-part',
        type=int,
        default=50,
        help='Number of items per output file (default: 50)'
    )

    parser.add_argument(
        '--output-dir',
        default='01-burp/xml_subdivision',
        help='Output directory for split files (default: 01-burp/xml_subdivision)'
    )

    args = parser.parse_args()

    try:
        split_burp_xml(
            input_file=args.input_file,
            output_dir=args.output_dir,
            items_per_part=args.items_per_part
        )
        return 0
    except Exception as e:
        print(f"[✗] Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
