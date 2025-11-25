#!/usr/bin/env python3
"""
Data Sanitization Script for GitHub Portfolio Publication
Redacts sensitive information from VAPT research documentation

Purpose: Prepare CNR research files for public/semi-public GitHub repository
Author: Federico Barsanti
Created: 2025-11-04
"""

import re
import os
import sys
from pathlib import Path
from typing import List, Tuple
import argparse

class GitHubSanitizer:
    """
    Sanitizes security research documentation by redacting sensitive data
    while preserving technical patterns for demonstration purposes.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.redaction_count = {}

        # Redaction patterns (pattern, replacement, description)
        self.patterns: List[Tuple[str, str, str]] = [
            # VINs (Vehicle Identification Numbers)
            (r'KNAC381AFR5192446', '[REDACTED_VIN]', 'Specific VIN'),
            (r'KNAC\w{13}', '[REDACTED_VIN]', 'VIN pattern'),

            # OAuth2 Tokens (base64-encoded)
            (r'ODZKNDE2YJMTMW[A-Z0-9]+', '[REDACTED_REFRESH_TOKEN]', 'refresh_token'),
            (r'refresh_token["\s:]+[A-Za-z0-9+/=]{40,}', 'refresh_token: "[REDACTED]"', 'refresh_token field'),
            (r'access_token["\s:]+[A-Za-z0-9+/=]{40,}', 'access_token: "[REDACTED]"', 'access_token field'),

            # UUIDs (preserve pattern, mask value)
            (r'f106d9ed-b8c5-4c9c-b782-476f21e97bc7', 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx', 'Automotive UUID'),
            (r'b5b66c5e-8712-4cf2-88f2-082195cf6c16', 'yyyyyyyy-yyyy-4yyy-yyyy-yyyyyyyyyyyy', 'Server device ID'),

            # Generic UUID pattern (if different UUIDs appear)
            (r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
             'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx', 'UUID Type 4'),

            # Device IDs in headers/JSON
            (r'Ccsp-Device-Id:\s*[a-f0-9-]+', 'Ccsp-Device-Id: [REDACTED]', 'Device ID header'),
            (r'"deviceId":\s*"[a-f0-9-]+"', '"deviceId": "[REDACTED]"', 'Device ID JSON'),

            # Hardcoded OAuth2 credentials
            (r'fdc85c00-0a2f-4c64-bcb4-2cfb1500730a', '[HARDCODED_CLIENT_ID]', 'OAuth2 client_id'),
            (r'client_secret["\s:]+secret', 'client_secret: "[REDACTED]"', 'Hardcoded secret'),

            # Email addresses (preserve pattern for test accounts)
            (r'[a-zA-Z0-9._%+-]+@automotive\.com', 'researcher@example.com', 'Automotive email'),
            (r'[a-zA-Z0-9._%+-]+@(hyundai|genesis)\.com', 'researcher@example.com', 'Automotive brand email'),

            # IP Addresses (partial redaction)
            (r'192\.168\.\d{1,3}\.\d{1,3}', '192.168.XXX.XXX', 'Private IPv4'),
            (r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', '10.XXX.XXX.XXX', 'Private IPv4'),

            # API Keys/Secrets (generic pattern - review manually)
            (r'"apiKey":\s*"[A-Za-z0-9+/=]{32,}"', '"apiKey": "[REDACTED]"', 'API key'),
            (r'"secret":\s*"[A-Za-z0-9+/=]{32,}"', '"secret": "[REDACTED]"', 'Secret field'),

            # Phone numbers (if any)
            (r'\+?\d{10,15}', '[REDACTED_PHONE]', 'Phone number'),

            # Authorization headers (preserve Bearer pattern)
            (r'Authorization:\s*Bearer\s+[A-Za-z0-9\-\._~\+/]+=*',
             'Authorization: Bearer [REDACTED_TOKEN]', 'Bearer token'),
        ]

    def sanitize_file(self, file_path: Path, output_path: Path) -> bool:
        """
        Sanitize a single file by applying all redaction patterns.
        Creates a NEW sanitized copy, preserving the original.

        Args:
            file_path: Path to the original file
            output_path: Path where sanitized copy will be written

        Returns:
            True if file was sanitized and written, False otherwise
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            original_content = content
            file_redactions = 0

            for pattern, replacement, description in self.patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    count = len(matches)
                    content = re.sub(pattern, replacement, content, flags=re.IGNORECASE)
                    file_redactions += count

                    # Track redaction statistics
                    if description not in self.redaction_count:
                        self.redaction_count[description] = 0
                    self.redaction_count[description] += count

                    if self.verbose:
                        print(f"  [{file_path.name}] Redacted {count}x {description}")

            # Always write output file (even if no changes)
            # This ensures the sanitized directory has complete structure
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)

            return content != original_content

        except Exception as e:
            print(f"❌ Error sanitizing {file_path}: {e}", file=sys.stderr)
            return False

    def sanitize_directory(self, input_dir: Path, output_dir: Path, file_patterns: List[str] = ['*.md', '*.txt', '*.json']) -> None:
        """
        Recursively sanitize all matching files in a directory.
        Creates NEW sanitized copies in output_dir, preserving originals in input_dir.

        Args:
            input_dir: Source directory with original files
            output_dir: Destination directory for sanitized copies
            file_patterns: List of glob patterns for files to process
        """
        total_files = 0
        modified_files = 0

        print(f"\n🔍 Scanning directory: {input_dir}")
        print(f"📁 Output directory: {output_dir}")

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        for pattern in file_patterns:
            for file_path in input_dir.rglob(pattern):
                # Skip certain directories
                if any(skip in file_path.parts for skip in ['.git', '__pycache__', 'node_modules', '.venv', 'sanitized']):
                    continue

                # Calculate output path (mirror directory structure)
                relative_path = file_path.relative_to(input_dir)
                output_path = output_dir / relative_path

                total_files += 1
                if self.sanitize_file(file_path, output_path):
                    modified_files += 1
                    print(f"✅ Sanitized: {relative_path}")
                else:
                    print(f"📄 Copied (no changes): {relative_path}")

        print(f"\n📊 Sanitization Summary:")
        print(f"  Files processed: {total_files}")
        print(f"  Files with redactions: {modified_files}")
        print(f"  Files copied unchanged: {total_files - modified_files}")
        print(f"\n🔐 Redaction Statistics:")
        for redaction_type, count in sorted(self.redaction_count.items(), key=lambda x: x[1], reverse=True):
            print(f"  {redaction_type}: {count} occurrences")

def main():
    parser = argparse.ArgumentParser(
        description='Sanitize VAPT research files for GitHub publication (creates NEW sanitized copies)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sanitize 3-reports directory to github-repo-sanitized output
  python3 sanitize_for_github.py 3-reports github-repo-sanitized

  # Sanitize with verbose output
  python3 sanitize_for_github.py 3-reports github-repo-sanitized -v

  # Sanitize specific file types only
  python3 sanitize_for_github.py docs output --patterns "*.md"

  # Auto-generate output directory name
  python3 sanitize_for_github.py 3-reports  # Creates 3-reports-sanitized/

IMPORTANT: This script creates NEW sanitized copies. Original files are NEVER modified.
        """
    )

    parser.add_argument(
        'input_directory',
        type=str,
        help='Source directory containing original files'
    )

    parser.add_argument(
        'output_directory',
        type=str,
        nargs='?',  # Optional
        help='Destination directory for sanitized copies (default: {input_directory}-sanitized)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--patterns',
        nargs='+',
        default=['*.md', '*.txt', '*.json'],
        help='File patterns to process (default: *.md *.txt *.json)'
    )

    args = parser.parse_args()

    input_dir = Path(args.input_directory).resolve()

    # Auto-generate output directory if not provided
    if args.output_directory:
        output_dir = Path(args.output_directory).resolve()
    else:
        output_dir = input_dir.parent / f"{input_dir.name}-sanitized"

    if not input_dir.exists():
        print(f"❌ Error: Input directory not found: {input_dir}", file=sys.stderr)
        sys.exit(1)

    if not input_dir.is_dir():
        print(f"❌ Error: Not a directory: {input_dir}", file=sys.stderr)
        sys.exit(1)

    if output_dir.exists():
        print(f"⚠️  Warning: Output directory already exists: {output_dir}")
        response = input("Overwrite existing files? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Aborted.")
            sys.exit(0)

    print("🔒 GitHub Data Sanitization Tool")
    print("=" * 60)
    print(f"Input directory:  {input_dir}")
    print(f"Output directory: {output_dir}")
    print(f"File patterns:    {', '.join(args.patterns)}")
    print(f"Mode:             CREATE NEW SANITIZED COPIES")
    print("=" * 60)

    # Confirm before proceeding
    response = input("\n✅ Original files will NOT be modified. Create sanitized copies? (yes/no): ")
    if response.lower() not in ['yes', 'y']:
        print("Aborted.")
        sys.exit(0)

    sanitizer = GitHubSanitizer(verbose=args.verbose)
    sanitizer.sanitize_directory(input_dir, output_dir, args.patterns)

    print("\n✅ Sanitization complete!")
    print(f"\n📁 Sanitized files created in: {output_dir}")
    print("\n⚠️  IMPORTANT NEXT STEPS:")
    print("  1. Review sanitized files manually")
    print("  2. Check for any remaining sensitive data")
    print("  3. Verify technical patterns are still readable")
    print(f"  4. Original files preserved in: {input_dir}")
    print(f"  5. Use sanitized files from: {output_dir} for GitHub")

if __name__ == '__main__':
    main()
