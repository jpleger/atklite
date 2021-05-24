# atklite

(Warning: this is old software, circa 2013 and needs to be updated to use more recent libraries)

atklite is a library intended to help easily determine identifiable attributes about files under investigation. With a simple usage syntax, the following information can be determined by calling applications:

- MD5 hash
- SHA-1 hash
- SHA-256 hash
- CRC32 checksum
- File size
- File type (from magic bytes)
- Fuzzy hash (CTPH) via ssdeep

atklite is primarily intended for use in analyzing malware samples but may be
useful for anyone looking for a simple API for analyzing files.

Additionally, atklite can be used as a binary storage system, utilizing a standard
filesystem to store the files in a sharded manner using the first n bytes of the
hash that a user chooses to use (md5, sha1, sha256 or sha512).

## Setup

### Requirements

- Python (tested with Python 2.7)
- [python-magic](https://pypi.python.org/pypi/python-magic/). On most systems this requires the libmagic library to be
  installed.
- Python ssdeep wrapper, one of either:
  - [python-ssdeep](http://github.com/DinoTools/python-ssdeep)
  - [pydeep](https://github.com/kbandla/pydeep)

### Installing Prerequisites

Installing the prerequisites on an ubuntu system is fairly easy.

First we must install the prerequisites for python-ssdeep::
    # apt-get install cython ssdeep python-dev

## Installation

Installation with pip is simple::

  $ pip install atklite

If installing from source, unpack the distribution tarball and then install as
follows::

```shell
$ python setup.py build
$ python setup.py install
```

### Configuration and use

Usage::

```txt
# From the cli using atk-info:
jpleger@jupiter:~$ atk-info ~/glyphicons-halflings-white.png
[-] Using binary store at: /home/jpleger/binary_store
```
