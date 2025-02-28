import os
import time
import hashlib
import shutil
import json
import binascii
import re
import magic  
import pandas as pd
from pathlib import Path

########################################################################
# 1) SIGNATURE-BASED HELPERS
########################################################################

def load_json_file(json_path):
    with open(json_path, 'r') as f:
        return json.load(f)

def magic_number(file_path, offset, length):
    with open(file_path, 'rb') as f:
        f.seek(offset)
        bytes_values = f.read(int(length))
    return binascii.hexlify(bytes_values).decode('utf-8').upper()

def format_hex(hex_string):
    return hex_string.replace(" ", "").upper()

def find_specific(possible_signatures, compare_str, extension):
    for sig in possible_signatures:
        if sig[2] == compare_str:
            return (sig[0], sig[1], sig[2], extension)
    return None

def identify_file_signature(file_path, signatures):
    magic_desc = magic.from_file(file_path)

    if magic_desc == "data":
        return ("N/A", "N/A", magic_desc, ".bin")
    if magic_desc.startswith("ASCII text") or magic_desc.startswith("UTF-8 Unicode"):
        return ("N/A", "N/A", magic_desc, ".txt")
    if magic_desc.startswith("DOS batch file"):
        return ("N/A", "N/A", magic_desc, ".bat")

    possible_signatures = []
    for sig in signatures['filesigs']:
        try:
            offset = int(sig["Header offset"]) * 2  
        except ValueError:
            offset = 0

        expected_hex = format_hex(sig["Header (hex)"])
        file_hex = magic_number(file_path, offset, len(expected_hex) / 2)

        if file_hex == expected_hex:
            possible_signatures.append((
                sig["Header (hex)"],
                sig["Header offset"],
                sig["File description"],
                sig["File extension"]
            ))

    if len(possible_signatures) == 1:
        return possible_signatures[0]

    if len(possible_signatures) > 1:
        if magic_desc.startswith("Microsoft Excel 2007+"):
            ms_sig = find_specific(possible_signatures, "MS Office 2007 documents", "XLSX")
            if ms_sig:
                return ms_sig
        if magic_desc.startswith("Microsoft PowerPoint 2007+"):
            ms_sig = find_specific(possible_signatures, "MS Office 2007 documents", "PPTX")
            if ms_sig:
                return ms_sig
        if magic_desc.startswith("Microsoft Word 2007+"):
            ms_sig = find_specific(possible_signatures, "MS Office 2007 documents", "DOCX")
            if ms_sig:
                return ms_sig

        for sig in possible_signatures:
            desc = sig[2]
            words = desc.split()
            for word in words:
                if re.search(re.escape(word), magic_desc, re.IGNORECASE):
                    return sig

            exts = sig[3].split("|")
            for ext in exts:
                if re.search(re.escape(ext), magic_desc, re.IGNORECASE):
                    return (sig[0], sig[1], sig[2], ext)

    return ("Unknown", "Unknown", magic_desc, ".bin")

########################################################################
# 2) OTHER HELPER FUNCTIONS
########################################################################

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

def sanitize_filename(filename):
    invalid_chars = r'<>:"/\|?*'
    for ch in invalid_chars:
        filename = filename.replace(ch, "_")
    return filename.rstrip('. ')

########################################################################
# 3) MAIN ANALYSIS FUNCTION
########################################################################

def analyze_file(file_path, recovered_folder, signatures, allowed_exts):
    results = {}
    results["original_file_path"] = file_path
    results["file_name"] = os.path.basename(file_path)

    # 1) Original SHA-256
    results["sha256_original"] = calculate_sha256(file_path)

    # 2) Magic number detection
    magic_info = detect_magic_number(file_path)
    results["magic_offset_hex"] = magic_info["offset_hex"]
    results["magic_bytes_hex"] = magic_info["magic_hex"]
    results["magic_ascii"] = magic_info["ascii"]

    # 3) Metadata
    metadata = get_basic_metadata(file_path)
    results.update(metadata)

    # 4) Identify file signature
    fileHeader, fileOffset, fileDesc, fileExt = identify_file_signature(file_path, signatures)
    # Ensure extension starts with '.'
    fileExt = fileExt.strip()
    if not fileExt.startswith("."):
        fileExt = "." + fileExt
    fileExt = fileExt.lower()

    # If recognized extension not in the set, fallback to '.bin'
    if fileExt not in allowed_exts:
        fileExt = ".bin"

    results["file_header"] = fileHeader
    results["file_header_offset"] = fileOffset
    results["file_description"] = fileDesc
    results["identified_extension"] = fileExt

    # 5) Recover the file
    os.makedirs(recovered_folder, exist_ok=True)
    original_name = os.path.basename(file_path)
    name_without_ext, _ = os.path.splitext(original_name)

    # Sanitize to prevent WinError 123
    safe_base = sanitize_filename(name_without_ext)
    safe_ext = sanitize_filename(fileExt)
    recovered_name = safe_base + safe_ext
    recovered_path = os.path.join(recovered_folder, recovered_name)
    shutil.copy2(file_path, recovered_path)

    results["recovered_file_path"] = recovered_path

    # 6) SHA-256 (Recovered)
    results["sha256_recovered"] = calculate_sha256(recovered_path)

    return results

########################################################################
# 4) MAIN ENTRY POINT
########################################################################

def main():
    folder_to_analyze = input("Enter the full path to the folder: ").strip()
    if not os.path.isdir(folder_to_analyze):
        print(f"[ERROR] The folder does not exist: {folder_to_analyze}")
        return
    
    json_path = "file_sigs.json"
    if not os.path.isfile(json_path):
        print(f"[ERROR] Signature file not found: {json_path}")
        return
    signatures = load_json_file(json_path)

    allowed_exts = {
        ".docx", ".pptx", ".xlsx", ".pdf", ".txt", ".bat",
        ".ps1", ".exe", ".dll", ".png", ".jpg"
    }

    recovered_folder = os.path.join(folder_to_analyze, "recovered_files")
    print(f"Analyzing all files in: {folder_to_analyze}\n")

    file_data = []

    for root, dirs, files in os.walk(folder_to_analyze):
        if os.path.abspath(root) == os.path.abspath(recovered_folder):
            continue

        for name in files:
            file_path = os.path.join(root, name)
            try:
                analysis = analyze_file(file_path, recovered_folder, signatures, allowed_exts)
            except Exception as e:
                print(f"[ERROR] Could not analyze file {file_path}: {e}")
                continue

            print(f"--- Analysis for File: {analysis['original_file_path']} ---")
            print(f"  File Name         : {analysis['file_name']}")
            print(f"  SHA-256 (Original): {analysis['sha256_original']}")
            print(f"  Magic Offset (hex): {analysis['magic_offset_hex']}")
            print(f"  Magic Bytes (hex) : {analysis['magic_bytes_hex']}")
            print(f"  Magic ASCII       : {analysis['magic_ascii']}")
            print(f"  File Header       : {analysis['file_header']}")
            print(f"  Header Offset     : {analysis['file_header_offset']}")
            print(f"  Description       : {analysis['file_description']}")
            print(f"  Guessed Extension : {analysis['identified_extension']}")
            print(f"  File Size (bytes) : {analysis['file_size_bytes']}")
            print(f"  Created Time      : {analysis['file_created']}")
            print(f"  Last Modified     : {analysis['last_modified']}")
            print(f"  Last Accessed     : {analysis['last_accessed']}")
            print(f"  Recovered File    : {analysis['recovered_file_path']}")
            print(f"  SHA-256 (Recovered): {analysis['sha256_recovered']}")
            print()

            file_data.append({
                "File Name": analysis["file_name"],
                "SHA-256 (Original)": analysis["sha256_original"],
                "Magic Number Offset (Hex)": analysis["magic_offset_hex"],
                "Magic Number Bytes (Hex)": analysis["magic_bytes_hex"],
                "Magic Number ASCII": analysis["magic_ascii"],
                "File Header (Hex)": analysis["file_header"],
                "Header Offset": analysis["file_header_offset"],
                "File Description": analysis["file_description"],
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
