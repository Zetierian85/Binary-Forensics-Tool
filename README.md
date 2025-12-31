# Python BFT ("Binary Forensics Tool")
A simple python3 tool for pulling forensic data from binary files, primarily supporting ELF format.

## Setup
This section should cover the requirements and configuration you need to run BFT successfully.
### 1. Clone BFT Locally
```
git clone https://github.com/Zetierian85/Binary-Forensics-Tool.git
cd Binary-Forensics-Tool
```
### 2. Create Python venv, install dependencies
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
The simplest way to use BFT is to point it at the binary you want to analyze,
```
python3 bft.py <BIN_PATH>
```
If the binary is in ELF format, BFT supports pulling the following information:
* `--basic` information (type, architecture, entry point)
* ELF `--section` information
* ELF `--header` information

If none of these options are provided, BFT assumes all flags should be set and prints all available information.
Otherwise, providing any of these flags implies only `--<filter>` information should be printed, for example:
```
$ python3 bft.py /bin/ls --basic

Metadata for /bin/ls:
Magic Number: 7f 45 4c 46 (.ELF)
ELF Type: ET_DYN
Architecture: EM_X86_64
Entry Point: 0x6d30
```
You can also have BFT generate a HTML-based report with the `--report` flag,
```
python3 bft.py /bin/ls --report ~/binary_report.html
```
The report BFT generates uses basic HTML/CSS and should be well supported by most web browsers.

<img width="1204" height="748" alt="image" src="https://github.com/user-attachments/assets/5883d07c-7d70-4d08-b323-b0f4e4fc4adf" />

Generic binary files are also lightly supported by BFT and will pull information provided by the filesystem,
```
$ python3 bft.py ~/generic.bin 

Metadata for /home/user/generic.bin:
Size: 13987
Last Modified: 2025-12-31 08:41:27
Creation Time: 2025-12-31 08:41:27
Last Accessed: 2025-12-31 08:41:28
MD5 Hash: fb1ee63ead295159ac115f7ff378d49d
```

Additional guidance can be found using the `--help` flag,
```
$ python3 bft.py --help

usage: bft.py [-h] [--path PATH] [--basic] [--section] [--header] [--report [REPORT]] [file]

Extract metadata from ELF or BIN files.

positional arguments:
  file               Path to the ELF or BIN file (can be provided positionally).

options:
  -h, --help         Show this help message and exit.
  --path PATH        Path to the ELF or BIN file.
  --basic            Print basic ELF metadata (Magic Number, ELF Type, Architecture, Entry Point).
  --section          Print ELF sections.
  --header           Print ELF program headers.
  --report [REPORT]  Generate an HTML report. Optionally specify output path (default: <filename>_report.html in current directory).
```

# Pending
Some general remaining TODO's for BFT include,
* Adding official support for other binary formats
* Adding sortable columns for ELF header information
* Support mypy and/or other linting tools
