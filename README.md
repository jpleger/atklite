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
- Fuzzy hash (CTPH) via [ssdeep](https://ssdeep-project.github.io/ssdeep/)
- First byte values of file
- Cymru Malware Hash Registry ([MHR](https://www.team-cymru.com/mhr)) status

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
- [dnspython](dnspython.org/)

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

### Usage overview
Usage (CLI):

```
$ atk-info /usr/bin/dash
using binary store at: /home/jdoe/binary_store
-- dash ------------------------------------------------------------------------
  Analysis time: 2023-03-17 05:59:17.375644
  File name:     dash
  File size:     125688
  File type:     ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f7ab02fc1b8ff61b41647c1e16ec9d95ba5de9f0, for GNU/Linux 3.2.0, stripped
  CRC-32:        dea50977
  MD5 hash:      7409ae3f7b10e059ee70d9079c94b097
  SHA1 hash:     42e94914c7800c7063c51d7a17aec3a2069a3769
  SHA256 hash:   4f291296e89b784cd35479fca606f228126e3641f5bcaee68dee36583d7c9483
  Fuzzy hash:    3072:BW795HHUunYzyVSlYV+tqOsDRC1wAtXqW6mfDrEDImbr:BWjHHZ2dtq3RFGqWzbrED7br
  First bytes:   7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
  Stored file:   /home/jdoe/binary_store/7/4/0/7409ae3f7b10e059ee70d9079c94b097
```

Python API (processing data input):

```python
>>> from json import dumps as json_dumps
>>> from atklite import FileAnalysis
>>> with open("/usr/bin/dash", "rb") as f:
...     data = f.read(100)
... 
>>> analysis = FileAnalysis(data=data)
>>> print(json_dumps(analysis.return_analysis(), indent=4))
```

```json
{
    "time": 1679031740.0616658,
    "isotime": "2023-03-17 05:42:20.061673",
    "md5": "2b17c2d5693b2257c7a1e09f00e5e2aa",
    "sha1": "ff1070796c5d75a284415a6269a42c89b0b385ac",
    "sha256": "13feaf307e36054cf7537965d8343714112a25674a13bc5f591ecb1fb61de65b",
    "sha512": "e658d0487a72e91f2b00099ad2eebecd2c5c7f5963f1adf861b76dc088b569199f43c866dbb1de7af2ad58b312e205c2e3ef3891e51229508059e034176284ab",
    "size": 100,
    "ftype": "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV)",
    "ssdeep": "3:Bnks//ZlllVrX/1llp/leulZpXltllvllvll/n:BnX//ZtBP/leulZ5",
    "crc32": "0c29b48e",
    "first_bytes": "7f45 4c46 0201 0100 0000 0000 0000 0000 03  .ELF............."
}
```

A file known to MHR:

```
$ atk-info -n 7ee6095ba8c4ed9fe11fbf5e703823e1aeae7f5443027738f55979b27ca57171.dll 
using binary store at: /home/jdoe/binary_store
-- 7ee6095ba8c4ed9fe11fbf5e703823e1aeae7f5443027738f55979b27ca57171.dll --------
  Analysis time: 2023-08-21 02:03:14.620973
  File name:     7ee6095ba8c4ed9fe11fbf5e703823e1aeae7f5443027738f55979b27ca57171.dll
  File size:     135168
  File type:     PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
  CRC-32:        013a7794
  MD5 hash:      81e56fd3b67ce33ef7150003985be7f4
  SHA1 hash:     6c739fcc6dea8cc65617ff184f1febcd5404143a
  SHA256 hash:   7ee6095ba8c4ed9fe11fbf5e703823e1aeae7f5443027738f55979b27ca57171
  Fuzzy hash:    3072:4ELogSZScYg+E/wmqpFQQT7J/AzMVWWRTBfItV74VZ:LofScb/wmqp+QPJ4zMVWWRTBgkj
  First bytes:   4d5a 9000 0300 0000 0400 0000 ffff 0000  MZ..............
  Cymru MHR:     2023-08-20T00:40:33 11 engines (37%)
```

The MHR lookup is performed as a TXT record, allowing us to capture the results
timestamp and number of engines detecting the file as malicious. atklite
estimates a percentage of supported engines (in the above sample, 11/30,
resulting in a 37% detection rate).
