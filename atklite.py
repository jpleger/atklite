import binascii
import hashlib
import itertools
import logging
import os
import re
import shutil
import time
from argparse import ArgumentParser
from datetime import datetime
from tempfile import gettempdir

import magic
import pkg_resources
import ssdeep

__application_name__ = __name__
__version__ = pkg_resources.get_distribution(__application_name__).version
__full_version__ = f"{__application_name__} {__version__}"


# Default file chunk buffer size
FILE_CHUNK_SIZE = 2048
# Default byte read count
BYTE_READ_COUNT = 16

SUPPORTED_HASH_LIBS = ("md5", "sha1", "sha256", "sha512")
FILE_STORE_DIR = "~/sample_store"


logging.basicConfig(level=logging.INFO, format="%(message)s")


class FileAnalysis:
    """
    Determine file attributes and return a dictionary of values.

    Pass in either a file path using the "filename" parameter or a data buffer
    using the "data" parameter.

    """

    results = {}

    results.update(
        analyzetime=time.ctime(),
        time=time.time(),
        analyze_isotime=datetime.utcnow(),
    )

    # XXX Unmunge this
    __ssd = ssdeep
    __ssd.hash_bytes = __ssd.hash
    __ssd.hash_file = __ssd.hash_from_file
    __ms = magic.Magic()

    def __init__(self, data=None, filename=None):
        if filename:
            self.analyze_file(filename)
        if data:
            self.analyze_data(data)

    def hash_data(self, data):
        for lib in SUPPORTED_HASH_LIBS:
            hl = getattr(hashlib, lib)
            self.results[lib] = hl(data).hexdigest()

    def hash_file(self, filename):
        "Return size, CRC-32 checksum, and hash values of input file"

        hash_libs = {}
        size = 0
        crc = 0
        for lib in SUPPORTED_HASH_LIBS:
            hash_libs[lib] = getattr(hashlib, lib)()
        for chunk in read_chunks(open(filename, "rb")):
            # We do this here so we don't have to read twice
            size += len(chunk)
            crc = binascii.crc32(chunk, crc) & 0xFFFFFFFF
            for lib in hash_libs:
                hash_libs[lib].update(chunk)
        self.results["size"] = size
        self.results["crc32"] = "%08x" % crc
        for lib in hash_libs:
            self.results[lib] = hash_libs[lib].hexdigest()

    def read_first_data_bytes(self, data, buf_size=BYTE_READ_COUNT):
        "Return encodings of first bytes of data"

        buf = bytes(data)[: (buf_size + 1)]
        val_hex = buf.hex(" ", -2)
        val_ascii = re.sub("[^\x20-\x7e]", ".", buf.decode("utf-8"))
        return "  ".join([val_hex, val_ascii])

    def read_first_file_bytes(self, filename, buf_size=BYTE_READ_COUNT):
        "Return encodings of first bytes of file"

        with open(filename, "rb") as f:
            fdata = f.read(buf_size)

        return self.read_first_data_bytes(fdata, buf_size)

    def analyze_data(self, data):
        if not data:
            return False
        self.hash_data(data)
        self.results["size"] = len(data)
        self.results["ftype"] = self.__ms.from_buffer(data)
        self.results["ssdeep"] = self.__ssd.hash_bytes(data)
        self.results["crc32"] = "%08x" % (binascii.crc32(data) & 0xFFFFFFFF)
        self.results["first_bytes"] = self.read_first_data_bytes(data)

    def analyze_file(self, filename):
        if not os.path.isfile(filename):
            raise IOError("File: %s doesn't exist" % filename)
        # Size and CRC-32 computation done inside the hash function so we
        # don't have to read multiple times.
        self.hash_file(filename)
        self.results["ftype"] = self.__ms.from_file(filename)
        self.results["ssdeep"] = self.__ssd.hash_file(filename)
        self.results["first_bytes"] = self.read_first_file_bytes(filename)

    def return_analysis(self):
        return self.results

    def dump(self):
        res = []
        for result in self.results:
            res.append("%s: %s" % (result, self.results[result]))
        return "\n".join(res)


class FileDB:
    """
    A tool for working with binaries stored in a traditional file system
    that are sharded by hash.

    This allows for very large scale binary storage by adding mountpoints.

    """

    file_store = os.path.join(gettempdir(), "binary_store")
    default_hash = "md5"  # or sha1 or sha256
    depth = 3
    create_dirs = False

    def __init__(
        self, file_store=None, depth=None, default_hash=None, create_dirs=None
    ):
        if file_store:
            self.file_store = os.path.abspath(os.path.expanduser(file_store))
        if depth:
            self.depth = depth
        if default_hash:
            self.default_hash = default_hash
        if create_dirs is not None:
            self.create_dirs = create_dirs
        if self.create_dirs:
            self.create_directory_structure()
        if self.default_hash not in SUPPORTED_HASH_LIBS:
            raise ValueError(
                "Unknown hash type: %s, valid types: %s"
                % (self.default_hash, ",".join(SUPPORTED_HASH_LIBS))
            )
        self.file_meta = dict()

    def create_directory_structure(self):
        hex_chars = "1234567890abcdef"
        for dst_dir in itertools.product(hex_chars, repeat=self.depth):
            dest_dir = os.path.join(self.file_store, *dst_dir)
            if not os.path.exists(dest_dir):
                os.makedirs(dest_dir, mode=0o775)
        self.create_dirs = False
        self.create_dirs = False

    def get_local_path(self, file_hash, file_store=None):
        """Get the path of a hash stored in the local sharded filesystem.

        :file_hash: The hash of the file to get the directory of.
        :file_store: Local directory where files are stored.
        """
        if not file_store:
            file_store = self.file_store
        return os.path.join(
            file_store, os.sep.join(list(file_hash[: self.depth]))
        )

    def get_file_location(self, file_hash, file_store=None):
        """
        Get the entire path of a file stored in the local sharded filesystem.

        :file_hash: The hash of the file to get the directory of.
        :file_store: Local directory where files are stored.
        """
        target_file = os.path.join(
            self.get_local_path(file_hash, file_store), file_hash
        )
        return target_file

    def write_file_data(self, data, file_hash=None):
        """Write the file data (typically a string or unicode data).

        :data: string or other data to be written
        :file_hash: if specified, will not run the `FileAnalysis` module.
        """
        file_info = {}
        if not file_hash:
            file_info = file_info.update(FileAnalysis(data=data).results)
            file_hash = file_info[self.default_hash]
        else:
            file_hash = file_info[self.default_hash] = file_hash
        target_file = self.get_file_location(file_hash)
        file_info["file_stored"] = target_file
        if not os.path.isfile(target_file):
            open(target_file, "wb").write(data)
        return file_info

    def open_fp(self, file_hash, *args, **kwargs):
        target_file = self.get_file_location(file_hash)
        if os.path.isfile(target_file):
            handle = open(target_file, *args, **kwargs)
            return handle
        else:
            raise IOError("Could not find file: %s" % target_file)

    def copy_file(self, src_filename, file_hash=None):
        if not file_hash:
            file_hash = FileAnalysis(filename=src_filename).results[
                self.default_hash
            ]
        target_file = self.get_file_location(file_hash)
        shutil.copy(src_filename, target_file)
        return file_hash

    def move_file(self, src_filename, file_hash=None):
        if not file_hash:
            file_hash = FileAnalysis(filename=src_filename).results[
                self.default_hash
            ]
        target_file = self.get_file_location(file_hash)
        shutil.move(src_filename, target_file)
        return file_hash


def read_chunks(f, chunk_size=FILE_CHUNK_SIZE):
    "Read file in chunks"

    while True:
        data = f.read(chunk_size)
        if not data:
            break
        yield data


def cli():
    "Main CLI entry point"

    description = "Identify file attributes."
    parser = ArgumentParser(description=description)
    parser.add_argument("file", nargs="+", help="input file")
    parser.add_argument(
        "-d", "--dir", default="~/binary_store", help="binary store directory"
    )
    parser.add_argument(
        "-c",
        "--create-dirs",
        action="store_true",
        help="create binary store directory structure",
    )
    parser.add_argument(
        "-m",
        "--move-file",
        action="store_true",
        help="move file to binary store instead of copying",
    )
    parser.add_argument(
        "-n", "--no-store", action="store_true", help="do not store file"
    )
    parser.add_argument(
        "-V",
        "--version",
        version=__full_version__,
        action="version",
        help="show program version",
    )
    args = parser.parse_args()

    filedb = FileDB(args.dir)

    if args or args.create_dirs:
        logging.info("using binary store at: %s", filedb.file_store)

    if args.create_dirs or not os.path.exists(filedb.file_store):
        filedb.create_directory_structure()
        logging.debug("  [+] Created Directory Structure")

    for f in args.file:
        try:
            fa = FileAnalysis(filename=f).return_analysis()
            fa["file_name"] = os.path.basename(f)
            if not args.no_store:
                if args.move_file:
                    filedb.move_file(f, fa["md5"])
                else:
                    filedb.copy_file(f, fa["md5"])
                fa["file_path"] = filedb.get_file_location(fa["md5"])
            logging.info(
                "-- %s %s", fa["file_name"], "-" * (76 - len(fa["file_name"]))
            )

            print(
                f"""  Analysis time: {fa['analyze_isotime']}
  File name:     {fa['file_name']}
  File size:     {fa['size']}
  File type:     {fa['ftype']}
  CRC-32:        {fa['crc32']}
  MD5 hash:      {fa['md5']}
  SHA1 hash:     {fa['sha1']}
  SHA256 hash:   {fa['sha256']}
  Fuzzy hash:    {fa['ssdeep']}
  First bytes:   {fa['first_bytes']}"""
            )

            if "file_path" in fa:
                print(f"  Stored file:   {fa['file_path']}")
        except IOError as e:
            parser.error("[ERROR] %s" % e)


if __name__ == "__main__":
    cli()
