import os
import time
import hashlib
import shutil
import mimetypes
import magic
import pandas as pd
from pathlib import Path

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def detect_magic_number(file_path, max_bytes=32):
    with open(file_path, "rb") as f:
        data = f.read(max_bytes)

    offset = 0
    magic_bytes = data[:4]  
    magic_hex = magic_bytes.hex().upper()
    magic_ascii = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in magic_bytes)

    return {
        "magic_hex": magic_hex,
        "offset_hex": hex(offset),
        "ascii": magic_ascii
    }

def get_basic_metadata(file_path):
    p = Path(file_path)
    stats = p.stat()

    creation_time = time.ctime(stats.st_ctime)
    mod_time = time.ctime(stats.st_mtime)
    acc_time = time.ctime(stats.st_atime)

    return {
        "file_size_bytes": stats.st_size,
        "file_created": creation_time,
        "last_modified": mod_time,
        "last_accessed": acc_time
    }

def identify_file_type(file_path):
    mime_detector = magic.Magic(mime=True)
    mime_type = mime_detector.from_file(file_path)

    extension = mimetypes.guess_extension(mime_type)
    if extension is None:
        extension = ".bin"

    return mime_type, extension

def analyze_file(file_path, recovered_folder):
    results = {}
    results["original_file_path"] = file_path

    # 1) SHA-256 (Original)
    results["sha256_original"] = calculate_sha256(file_path)

    # 2) Magic number detection
    magic_info = detect_magic_number(file_path)
    results["magic_offset_hex"] = magic_info["offset_hex"]
    results["magic_bytes_hex"] = magic_info["magic_hex"]
    results["magic_ascii"] = magic_info["ascii"]

    # 3) Basic metadata
    metadata = get_basic_metadata(file_path)
    results.update(metadata)  # includes file_size_bytes, file_created, last_modified, last_accessed

    # 4) Identify file type
    mime_type, extension = identify_file_type(file_path)
    results["mime_type"] = mime_type
    results["identified_extension"] = extension

    # 5) Recover the file
    os.makedirs(recovered_folder, exist_ok=True)
    original_name = os.path.basename(file_path)
    name_without_ext, _ = os.path.splitext(original_name)
    recovered_name = name_without_ext + extension
    recovered_path = os.path.join(recovered_folder, recovered_name)

    shutil.copy2(file_path, recovered_path)
    results["recovered_file_path"] = recovered_path

    # 6) SHA-256 (Recovered)
    results["sha256_recovered"] = calculate_sha256(recovered_path)

    return results

def main():
    folder_to_analyze = input("Enter the full path to the folder: ").strip()

    if not os.path.isdir(folder_to_analyze):
        print(f"[ERROR] The folder does not exist: {folder_to_analyze}")
        return

    recovered_folder = os.path.join(folder_to_analyze, "recovered_files")

    print(f"Analyzing all files in: {folder_to_analyze}\n")

    file_data = []

    for root, dirs, files in os.walk(folder_to_analyze):
        if os.path.abspath(root) == os.path.abspath(recovered_folder):
            continue
        
        for name in files:
            file_path = os.path.join(root, name)
            try:
                analysis = analyze_file(file_path, recovered_folder)
            except Exception as e:
                print(f"[ERROR] Could not analyze file {file_path}: {e}")
                continue

            print(f"--- Analysis for File: {analysis['original_file_path']} ---")
            print(f"  SHA-256 (Original): {analysis['sha256_original']}")
            print(f"  Magic Offset (hex): {analysis['magic_offset_hex']}")
            print(f"  Magic Bytes  (hex): {analysis['magic_bytes_hex']}")
            print(f"  Magic ASCII       : {analysis['magic_ascii']}")
            print(f"  MIME Type         : {analysis['mime_type']}")
            print(f"  Guessed Extension : {analysis['identified_extension']}")
            print(f"  File Size (bytes) : {analysis['file_size_bytes']}")
            print(f"  Created Time      : {analysis['file_created']}")
            print(f"  Last Modified     : {analysis['last_modified']}")
            print(f"  Last Accessed     : {analysis['last_accessed']}")
            print(f"  Recovered File    : {analysis['recovered_file_path']}")
            print(f"  SHA-256 (Recovered): {analysis['sha256_recovered']}")
            print()

            file_data.append({
                "SHA-256 (Original)": analysis["sha256_original"],
                "Magic Number Offset (Hex)": analysis["magic_offset_hex"],
                "Magic Number Bytes (Hex)": analysis["magic_bytes_hex"],
                "Magic Number ASCII": analysis["magic_ascii"],
                "MIME Type": analysis["mime_type"],
                "Guessed Extension": analysis["identified_extension"],
                "File Size (Bytes)": analysis["file_size_bytes"],
                "Created Time": analysis["file_created"],
                "Last Modified": analysis["last_modified"],
                "Last Accessed": analysis["last_accessed"],
                "SHA-256 (Recovered)": analysis["sha256_recovered"]
            })

    df = pd.DataFrame(file_data)
    output_file = os.path.join(folder_to_analyze, "file_analysis.xlsx")
    df.to_excel(output_file, index=False)

    print(f"\nAnalysis complete! Results saved to: {output_file}")
    print(f"Recovered files placed in: {recovered_folder}")

if __name__ == "__main__":
    main()
