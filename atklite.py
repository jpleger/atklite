#!/usr/bin/env python
"""
ATKLite

Python library for analyzing unknown binaries.
"""
__version__ = '1.0-release'
import hashlib
import os
import shutil
import time
import sys
import binascii
import itertools
from tempfile import gettempdir
from optparse import OptionParser

ERROR = False

try:
    import magic
except ImportError:
    print >> sys.stderr, "[!] Warning: python-magic required for file analysis."
    print >> sys.stderr, "    install: https://pypi.python.org/pypi/python-magic/"
    ERROR = True

try:
    import ssdeep
    if hasattr(ssdeep, 'hash_from_file'):
        FUZZYLIB = 'ssdeep'    # http://github.com/DinoTools/python-ssdeep
    elif hasattr(ssdeep, 'hash_file'):
        FUZZYLIB = 'pyssdeep'  # http://code.google.com/p/pyssdeep/
except ImportError:
    try:
        import pydeep
        FUZZYLIB = 'pydeep'            # https://github.com/kbandla/pydeep
    except ImportError:
        print >> sys.stderr, "[!] Warning: ssdeep library required for file analysis."
        print >> sys.stderr, "    install: https://github.com/DinoTools/python-ssdeep -or-"
        print >> sys.stderr, "             https://github.com/kbandla/pydeep"
        ERROR = True


# From Stack Overflow
def read_chunks(file_object, chunk_size=2048):
    """ Read file in chunks """
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data


class FileAnalysis:
    """
    Determine file attributes and return dictionary of values.

    Pass in either a file path using the 'filename' parameter or a data buffer
    using the 'data' parameter.

    """
    results = {'analyzetime': time.ctime(), 'time': time.time()}
    hash_libs = ('md5', 'sha1', 'sha256', 'sha512')
    if ERROR:
        sys.exit("This function requires dependencies that aren't satisfied")

    # Handle multiple ssdeep binding options by aligning them to consistent
    # namespace.
    if FUZZYLIB == 'ssdeep':
        __ssd = ssdeep
        __ssd.hash_bytes = __ssd.hash
        __ssd.hash_file = __ssd.hash_from_file
    elif FUZZYLIB == 'pyssdeep':
        __ssd = ssdeep.ssdeep()
    elif FUZZYLIB == 'pydeep':
        __ssd = pydeep
    __ms = magic.Magic()

    def __init__(self, data=None, filename=None):
        if filename:
            self.analyze_file(filename)
        if data:
            self.analyze_data(data)

    def hash_data(self, data):
        for lib in self.hash_libs:
            hl = getattr(hashlib, lib)
            self.results[lib] = hl(data).hexdigest()

    def hash_file(self, filename):
        hash_libs = {}
        size = 0
        crc = 0
        for lib in self.hash_libs:
            hash_libs[lib] = getattr(hashlib, lib)()
        for chunk in read_chunks(open(filename, 'rb')):
            # We do this here so we don't have to read twice
            size += len(chunk)
            crc = binascii.crc32(chunk, crc) & 0xffffffff
            for lib in hash_libs:
                hash_libs[lib].update(chunk)
        self.results['size'] = size
        self.results['crc32'] = '%08x' % crc
        for lib in hash_libs:
            self.results[lib] = hash_libs[lib].hexdigest()

    def analyze_data(self, data):
        if not data:
            return False
        self.hash_data(data)
        self.results['size'] = len(data)
        self.results['ftype'] = self.__ms.from_buffer(data)
        self.results['ssdeep'] = self.__ssd.hash_bytes(data)
        self.results['crc32'] = '%08x' % (binascii.crc32(data) & 0xffffffff)

    def analyze_file(self, filename):
        if not os.path.isfile(filename):
            raise IOError("File: %s doesn't exist" % filename)
        # Size and CRC-32 computation done inside the hash function so we
        # don't have to read multiple times.
        self.hash_file(filename)
        self.results['ftype'] = self.__ms.from_file(filename)
        self.results['ssdeep'] = self.__ssd.hash_file(filename)

    def return_analysis(self):
        return self.results

    def dump(self):
        res = []
        for result in self.results:
            res.append("%s: %s" % (result, self.results[result]))
        return "\n".join(res)


class FileDB:
    """
    A tool for working with binaries stored in a traditional file system that are sharded by hash.

    This allows for very large scale binary storage by adding mountpoints.
    """
    file_store = os.path.join(gettempdir(), 'binary_store')
    default_hash = 'md5'  # or sha1 or sha256
    depth = 3
    create_dirs = False

    def __init__(self, file_store=None, depth=None, default_hash=None, create_dirs=None):
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
        if self.default_hash not in FileAnalysis.hash_libs:
            raise ValueError("Unknown hash type: %s, valid types: %s" % (self.default_hash,
                                                                         ",".join(FileAnalysis.hash_libs)))
        self.file_meta = dict()

    def create_directory_structure(self):
        hex_chars = '1234567890abcdef'
        for dst_dir in itertools.product(hex_chars, repeat=self.depth):
            dest_dir = os.path.join(self.file_store, *dst_dir)
            if not os.path.exists(dest_dir):
                os.makedirs(dest_dir, mode=0775)
        self.create_dirs = False
        self.create_dirs = False

    def get_local_path(self, file_hash, file_store=None):
        """ Get the path of a hash stored in the local sharded filesystem.

        :file_hash: The hash of the file to get the directory of.
        :file_store: Local directory where files are stored.
        """
        if not file_store:
            file_store = self.file_store
        return os.path.join(file_store, os.sep.join(list(file_hash[:self.depth])))

    def get_file_location(self, file_hash, file_store=None):
        """ Get the entire path of a file stored in the local sharded filesystem.

        :file_hash: The hash of the file to get the directory of.
        :file_store: Local directory where files are stored.
        """
        target_file = os.path.join(self.get_local_path(file_hash, file_store), file_hash)
        return target_file

    def write_file_data(self, data, file_hash=None):
        """ Write the file data (typically a string or unicode data).

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
        file_info['file_stored'] = target_file
        if not os.path.isfile(target_file):
            open(target_file, 'wb').write(data)
        return file_info

    def open_fp(self, file_hash, *args, **kwargs):
        target_file = self.get_file_location(file_hash)
        if os.path.isfile(target_file):
            handle = open(target_file, *args, **kwargs)
            return handle
        else:
            raise IOError('Could not find file: %s' % target_file)

    def copy_file(self, src_filename, file_hash=None):
        if not file_hash:
            file_hash = FileAnalysis(filename=src_filename).results[self.default_hash]
        target_file = self.get_file_location(file_hash)
        shutil.copy(src_filename, target_file)
        return file_hash

    def move_file(self, src_filename, file_hash=None):
        if not file_hash:
            file_hash = FileAnalysis(filename=src_filename).results[self.default_hash]
        target_file = self.get_file_location(file_hash)
        shutil.move(src_filename, target_file)
        return file_hash


def main():
    usage = "usage: %prog [options] FILE"
    parser = OptionParser(usage, version="atklite %s" % __version__)
    parser.add_option('-d', '--dir', dest="store_dir", default="~/binary_store",
                      help="Binary store directory")
    parser.add_option('-c', '--create-dirs', dest="create_dirs", default=False,
                      action="store_true", help="Create binary store directory structure")
    parser.add_option('-m', '--move-file', dest="move_file", default=False,
                      action="store_true", help="Move instead of copy file")
    parser.add_option('-n', '--no-store', dest="no_store", default=False,
                      action="store_true", help="Do not store any files")
    (options, args) = parser.parse_args()
    filedb = FileDB(options.store_dir)
    if args or options.create_dirs:
        print "[-] Using binary store at: %s" % filedb.file_store
    if options.create_dirs or not os.path.exists(filedb.file_store):
        filedb.create_directory_structure()
        print "  [+] Created Directory Structure"
    if not args and not options.create_dirs:
        parser.print_help()
        sys.exit(-1)
    for f in args:
        try:
            analysis = FileAnalysis(filename=f).return_analysis()
            analysis['file_name'] = os.path.basename(f)
            if not options.no_store:
                if options.move_file:
                    filedb.move_file(f, analysis['md5'])
                else:
                    filedb.copy_file(f, analysis['md5'])
                analysis['file_path'] = filedb.get_file_location(analysis['md5'])
            print "-- %s " % analysis['file_name'] + "-" * (76 - len(analysis['file_name']))
            print """  Analyze time: %(analyzetime)s
  File name:    %(file_name)s
  File size:    %(size)s
  File type:    %(ftype)s
  CRC-32:       %(crc32)s
  MD5 hash:     %(md5)s
  SHA1 hash:    %(sha1)s
  SHA256 hash:  %(sha256)s
  Fuzzy hash:   %(ssdeep)s""" % analysis
            if 'file_path' in analysis:
                print "  Stored File:  %s" % analysis['file_path']
        except IOError as e:
            print >> sys.stderr, "[Error] %s" % e

if __name__ == '__main__':
    main()
