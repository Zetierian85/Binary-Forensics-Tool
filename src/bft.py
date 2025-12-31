import os
import hashlib
from datetime import datetime
from elftools.elf.elffile import ELFFile
import argparse
import json

ELF_MAGIC = b'\x7fELF'

# Fetch metadata for ELF files
def get_elf_metadata(file_path, options):
    metadata = {}

    try:
        with open(file_path, 'rb') as f:
            elf = ELFFile(f)

            # Fetch ELF headers and format magic number as hex and ASCII
            magic_bytes = elf.header['e_ident']['EI_MAG']
            hex_str = ' '.join(f'{b:02x}' for b in magic_bytes)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in magic_bytes)
            metadata['Magic Number'] = f"{hex_str} ({ascii_str})"
            
            # ELF header info (--header, --basic)
            if 'basic' in options or 'header' in options:
                metadata['ELF Type'] = elf.header['e_type']
                metadata['Architecture'] = elf.header['e_machine']
                metadata['Entry Point'] = hex(elf.header['e_entry'])

            # ELF binary section info (--section)
            if 'section' in options:
                sections = [section.name for section in elf.iter_sections() if section.name]
                metadata['Sections'] = sections

            # ELF memory header info (--header)
            if 'header' in options:
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
            # TODO: Explicitly add support for certain binary types
            else:
                return 'bin'
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

def generate_html_report(file_path, metadata, file_type, output_path):
    """Generate a HTML report from template"""
    
    # Find template file in the same directory as this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(script_dir, 'report_template.html')
    
    if not os.path.exists(template_path):
        print(f"Error: Template file not found at {template_path}")
        return False
    
    # Read template
    with open(template_path, 'r') as f:
        html_template = f.read()
    
    # Prepare data
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    basename = os.path.basename(file_path)
    
    # Build basic info items HTML
    basic_info_html = ""
    if isinstance(metadata, dict):
        if 'Magic Number' in metadata:
            basic_info_html += f"""
                    <div class="info-item">
                        <div class="label">Magic Number</div>
                        <div class="value" style="font-family: 'Courier New', monospace;">{metadata['Magic Number']}</div>
                    </div>
"""
        
        for key in ['ELF Type', 'Architecture', 'Entry Point', 'Size', 'MD5 Hash', 'Last Modified', 'Creation Time', 'Last Accessed']:
            if key in metadata:
                value = metadata[key]
                basic_info_html += f"""
                    <div class="info-item">
                        <div class="label">{key}</div>
                        <div class="value">{value}</div>
                    </div>
"""
    
    # Build sections HTML
    sections_html = ""
    if isinstance(metadata, dict) and 'Sections' in metadata and metadata['Sections']:
        sections_html = """
            <div class="section">
                <h3>ELF Sections</h3>
                <div class="sections-list">
"""
        for section in metadata['Sections']:
            sections_html += f'                    <div class="section-item">{section}</div>\n'
        
        sections_html += """
                </div>
            </div>
"""
    
    # Build program headers HTML
    program_headers_html = ""
    if isinstance(metadata, dict) and 'Program Headers' in metadata and metadata['Program Headers']:
        program_headers_html = """
            <div class="section">
                <h3>Program Headers</h3>
                <div class="program-headers">
                    <table>
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Offset</th>
                                <th>Virtual Address</th>
                                <th>Physical Address</th>
                                <th>File Size</th>
                                <th>Memory Size</th>
                            </tr>
                        </thead>
                        <tbody>
"""
        
        for ph in metadata['Program Headers']:
            program_headers_html += f"""
                            <tr>
                                <td>{ph['Type']}</td>
                                <td><code>{ph['Offset']}</code></td>
                                <td><code>{ph['Virtual Address']}</code></td>
                                <td><code>{ph['Physical Address']}</code></td>
                                <td>{ph['File Size']}</td>
                                <td>{ph['Memory Size']}</td>
                            </tr>
"""
        
        program_headers_html += """
                        </tbody>
                    </table>
                </div>
            </div>
"""
    
    # Replace placeholders in template
    html_output = html_template.replace('{{BASENAME}}', basename)
    html_output = html_output.replace('{{TIMESTAMP}}', timestamp)
    html_output = html_output.replace('{{FILE_TYPE}}', file_type.upper())
    html_output = html_output.replace('{{FILE_PATH}}', file_path)
    html_output = html_output.replace('{{BASIC_INFO}}', basic_info_html)
    html_output = html_output.replace('{{SECTIONS}}', sections_html)
    html_output = html_output.replace('{{PROGRAM_HEADERS}}', program_headers_html)
    
    # Write output
    try:
        with open(output_path, 'w') as f:
            f.write(html_output)
        print(f"Report generated successfully: {output_path}")
        return True
    except Exception as e:
        print(f"Error writing report: {e}")
        return False

def print_metadata(file_path, options):
    # Detect file type by magic bytes instead of extension
    file_type = detect_file_type(file_path)

    if file_type is None:
        print("Unable to detect file type")
        exit(-1)

    if file_type == 'elf':
        metadata = get_elf_metadata(file_path, options)
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
    
    return metadata, file_type

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
    
    # Add options for --section, --header, --basic
    parser.add_argument(
        '--basic', 
        action='store_true', 
        help="Print basic ELF metadata (Magic Number, ELF Type, Architecture, Entry Point)."
    )
    parser.add_argument(
        '--section', 
        action='store_true', 
        help="Print ELF sections."
    )
    parser.add_argument(
        '--header', 
        action='store_true', 
        help="Print ELF program headers."
    )
    parser.add_argument(
        '--report',
        nargs='?',
        const='',
        help="Generate an HTML report. Optionally specify output path (default: <filename>_report.html in current directory)."
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

    # Handle filter flag options
    options = []
    if args.basic:
        options.append('basic')
    if args.section:
        options.append('section')
    if args.header:
        options.append('header')

    if not options:
        options = ['basic', 'section', 'header']

    # Print metadata
    metadata, file_type = print_metadata(file_path, options)
    
    # Handle report option
    if args.report:
        if args.report == '':
            basename = os.path.basename(file_path)
            report_filename = f"{basename}_report.html"
            report_path = os.path.join(os.getcwd(), report_filename)
        else:
            report_path = args.report
        
        generate_html_report(file_path, metadata, file_type, report_path)

if __name__ == "__main__":
    main()
