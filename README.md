# atklite
atklite is a library intended to help easily determine identifiable
attributes about files under investigation. With a simple usage syntax,
the following information can be determined by calling applications:

- MD5 hash
- SHA-1 hash
- SHA-256 hash
- CRC32 checksum
- File size
- File type (from magic bytes)
- Fuzzy hash (CTPH) via ssdeep
- First byte values of file

atklite is primarily intended for use in analyzing malware samples but may be
useful for anyone looking for a simple API or command line tool for triaging
files.

Additionally, atklite can be used as a binary storage system, utilizing a standard
filesystem to store the files in a sharded manner using the first N bytes of the
hash that a user chooses to use (MD5, SHA-1, SHA-256 or SHA-512).

## Setup

### Requirements
- Python 3 (tested with Python 3.10)
- [libmagic](https://www.darwinsys.com/file/)
- [ssdeep](https://github.com/ssdeep-project/ssdeep)

The following modules are installed automatically:
- [python-magic](https://pypi.python.org/pypi/python-magic/)
- [ssdeep](https://pypi.org/project/ssdeep/)

### Installing prerequisites
Installing the prerequisites on an Debian/Ubuntu system is simple.

First install the prerequisites for python-ssdeep and python-magic:

    apt install ssdeep python3-dev libmagic1 libfuzzy-dev libfuzzy2

## Installation
atklite is available on PyPI. Install with [pip](https://pip.pypa.io/):

    python3 -m pip install atklite

If you just want to run the installed command line utility (`atk-info`), try
out [pipx](https://pypa.github.io/pipx/):

    pipx install atklite

### Configuration and use
Usage (CLI):

    atk-info ~/glyphicons-halflings-white.png

