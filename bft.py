import os
import hashlib
from datetime import datetime
from elftools.elf.elffile import ELFFile
import argparse

ELF_MAGIC = b'\x7fELF'

# Fetch metadata for ELF files
def get_elf_metadata(file_path):
    metadata = {}
    try:
        with open(file_path, 'rb') as f:
            elf = ELFFile(f)
            
            # Fetch ELF headers and format magic number as hex and ASCII
            magic_bytes = elf.header['e_ident']['EI_MAG']
            hex_str = ' '.join(f'{b:02x}' for b in magic_bytes)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in magic_bytes)
            metadata['Magic Number'] = f"{hex_str} ({ascii_str})"
            
            metadata['ELF Type'] = elf.header['e_type']
            metadata['Architecture'] = elf.header['e_machine']
            metadata['Entry Point'] = hex(elf.header['e_entry'])
            
            # Fetch all ELF sections, filter out empty section names
            sections = [section.name for section in elf.iter_sections() if section.name]
            metadata['Sections'] = sections
            
            # Fetch program headers and memory segments
            program_headers = []
            for ph in elf.iter_segments():
                program_headers.append({
                    'Type': ph['p_type'],
                    'Offset': hex(ph['p_offset']),
                    'Virtual Address': hex(ph['p_vaddr']),
                    'Physical Address': hex(ph['p_paddr']),
                    'File Size': ph['p_filesz'],
                    'Memory Size': ph['p_memsz']
                })
            metadata['Program Headers'] = program_headers
    except Exception as e:
        metadata['Error'] = str(e)
    
    return metadata

# Fetch metadata for BIN files
def get_bin_metadata(file_path):
    metadata = {}
    if not os.path.isfile(file_path):
        return "File does not exist."
    
    # Get basic file metadata
    metadata["Size"] = os.path.getsize(file_path)
    metadata["Last Modified"] = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
    metadata["Creation Time"] = datetime.fromtimestamp(os.path.getctime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
    metadata["Last Accessed"] = datetime.fromtimestamp(os.path.getatime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
    
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    metadata["MD5 Hash"] = hash_md5.hexdigest()
    
    return metadata

# Detect file type from magic bytes
def detect_file_type(file_path):
    try:
        with open(file_path, 'rb') as f:
            magic = f.read(4)
            if magic == ELF_MAGIC:
                return 'elf'
            # TODO: Explicitely add support for certain binary types
            else:
                return 'bin'
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

def print_metadata(file_path):
    # Detect file type by magic bytes instead of extension
    file_type = detect_file_type(file_path)
    
    if file_type is None:
        print("Unable to detect file type")
        exit(-1)
    
    if file_type == 'elf':
        metadata = get_elf_metadata(file_path)
    elif file_type == 'bin':
        metadata = get_bin_metadata(file_path)
    else:
        print(f"File type '{file_type}' not supported")
        exit(-1)
    
    if isinstance(metadata, dict):
        print(f"Metadata for {file_path}:")
        for key, value in metadata.items():
            if isinstance(value, list):
                print(f"{key}:")
                for item in value:
                    print(f"  - {item}")
            else:
                print(f"{key}: {value}")
    else:
        print(metadata)

def main():
    # Configure argparse
    parser = argparse.ArgumentParser(description="Extract metadata from ELF or BIN files.")
    parser.add_argument(
        '--path', 
        type=str, 
        help="Path to the ELF or BIN file.",
        required=False
    )
    parser.add_argument(
        'file', 
        type=str, 
        nargs='?', 
        help="Path to the ELF or BIN file (can be provided positionally)."
    )
    
    # Parse args
    args = parser.parse_args()
    
    # Check for --path and positional arg
    if args.path:
        file_path = args.path
    elif args.file:
        file_path = args.file
    else:
        print("Error: No file path provided.")
        return
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return
    
    print_metadata(file_path)

if __name__ == "__main__":
    main()
