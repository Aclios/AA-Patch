from utils import EndianBinaryFileWriter, EndianBinaryFileReader, EndianBinaryStreamWriter, get_file_hash, get_file_data, write_file_data
from configparser import ConfigParser
from pathlib import Path
from bsdiff4 import diff, patch

MAGIC = b'AAP\x00'

def build_patch(config_filepath : str, ori_root : str, new_data : list[tuple[str, int]], patch_filepath : str):
    config = ConfigParser()
    config.read(config_filepath)

    print('Calculating hashes...')
    files_data : list[tuple[str, int, bytes, str]] = []
    for new_root, flag in new_data:
        for ori_filepath in Path(ori_root).rglob('*'):
            if ori_filepath.is_file():
                rel_path = ori_filepath.relative_to(ori_root)
                new_filepath = new_root / rel_path
                if new_filepath.is_file():
                    ori_hash = get_file_hash(ori_filepath)
                    new_hash = get_file_hash(new_filepath)
                    if ori_hash != new_hash:
                        files_data.append([str(rel_path), flag, ori_hash, new_root])

    with EndianBinaryFileWriter(patch_filepath) as f:
        f.write(MAGIC)
        f.write_UInt16(int(config['general']['version']))
        f.write_UInt16(int(config['general']['flag']))
        f.write_UInt16(int(config['version']['major']))
        f.write_UInt16(int(config['version']['minor']))
        f.write_UInt32(len(files_data))

        f.write(bytes(0x110 * len(files_data)))
        for idx, (filepath, flag, ori_hash, new_root) in enumerate(files_data):
            print(f'Calculating patch for {filepath}...')
            offset = f.tell()
            ori_data = get_file_data(Path(ori_root) / filepath)
            new_data = get_file_data(Path(new_root) / filepath)
            patch = diff(ori_data, new_data)
            f.write(patch)
            f.seek(0x10 + 0x110 * idx)
            assert len(filepath) <= 0x100, 'Filepath length must not exceed 256 characters'
            f.write_string(filepath, encoding='utf-8')
            f.write(bytes(0x100 - len(filepath)))
            f.write(ori_hash)
            f.write_UInt32(flag)
            f.write_UInt32(offset)
            f.write_UInt32(len(patch))
            f.seek(0, 2)
 
class AAPatchFile:
    def read(self, f : EndianBinaryFileReader):
        self.hash = f.read(4)
        self.flag = f.read_UInt32()
        self.offset = f.read_UInt32()
        self.data_size = f.read_UInt32()
        return self

    def new(self, hash : bytes, flag : int, offset : int, data_size : int):
        self.hash = hash
        self.flag = flag
        self.offset = offset
        self.data_size = data_size
        return self

    def get_data(self, f : EndianBinaryFileReader):
        f.seek(self.offset)
        return f.read(self.data_size)
    
    def write_bytes(self, f : EndianBinaryFileWriter):
        f.write(self.hash)
        f.write_UInt32(self.flag)
        f.write_UInt32(self.offset)
        f.write_UInt32(self.data_size)

class AAPatchEntry:
    filepath : str = ''
    files : list[AAPatchFile] = []

    def read(self, f : EndianBinaryFileReader):
        file_count = f.read_UInt32()
        f.read(12)
        self.filepath = f.read(0x100).decode().rstrip('\x00')
        self.files = [AAPatchFile().read(f) for _ in range(file_count)]
        return self

    def new(self, filepath : str, files : list[AAPatchFile]):
        self.filepath = filepath
        self.files = files
        return self

    def write_bytes(self, f : EndianBinaryFileWriter):
        f.write_UInt32(len(self.files))
        f.write(bytes(12))
        filepath_bytes = self.filepath.encode('utf-8')
        f.write(filepath_bytes + bytes(0x100 - len(filepath_bytes)))
        for file in self.files: file.write_bytes(f)

    def get_patch_file(self, hash : bytes, flags : list[int]):
        files_with_correct_hash = [file for file in self.files if file.hash == hash and (file.flag in flags or file.flag == 0)]
        if len(files_with_correct_hash) == 0:
            raise Exception(f'File {self.filepath}: no patch has a corresponding hash to the input file')
        if len(files_with_correct_hash) == 1:
            return files_with_correct_hash[0]
        else:
            return max(files_with_correct_hash, key=lambda e : e.flag )
    
class OriginalFileData:
    hash : bytes
    root_path : str

    def __init__(self, hash : bytes, root_path : str):
        self.hash = hash
        self.root_path = root_path

class DestinationFileData:
    hash : bytes
    root_path : str
    flag : int

    def __init__(self, hash : bytes, root_path : str, flag : int):
        self.hash = hash
        self.root_path = root_path
        self.flag = flag

class AAPatch:
    version: int = 0
    flag: int = 0
    major: int = 0
    minor: int = 1
    _original_files: dict[str, list[OriginalFileData]] = {}
    _destination_files: dict[str, list[DestinationFileData]] = {}
    entries : list[AAPatchEntry] = []
    
    def read(self, filepath : str):
        self.filepath = filepath
        with EndianBinaryFileReader(filepath) as f:
            f.check_magic(MAGIC)
            self.version = f.read_UInt16()
            assert self.version == 0, 'Only version 0 is supported'
            self.flag = f.read_UInt16()
            self.major_version = f.read_UInt16()
            self.minor_version = f.read_UInt16()
            self.entry_count = f.read_UInt32()
            self.base_data_offset = f.read_UInt32()
            f.read(12)
            self.entries = [AAPatchEntry().read(f) for _ in range(self.entry_count)]

    def load_origin(self, root_dir : str):
        '''Load all files from a directory and its subdirectories as original files (files before modifications).\n\nCalculate their hashes.'''
        for origin_filepath in Path(root_dir).rglob('*'):
            if origin_filepath.is_file():
                filehash = get_file_hash(origin_filepath)
                rel_path = str(origin_filepath.relative_to(root_dir))
                if not rel_path in self._original_files: #untracked file
                    self._original_files[rel_path] = [OriginalFileData(filehash, str(root_dir))]
                elif all([filehash != data.hash for data in self._original_files[rel_path]]): #tracked file, but with a different hash
                    self._original_files[rel_path].append(OriginalFileData(filehash, str(root_dir)))

    def load_destination(self, root_dir : str, flag : int = 0):
        '''Load all files from a directory and its subdirectories as destination files (files after modifications), and associate the given flag to them.\n\nCalculate their hashes.'''
        for dest_filepath in Path(root_dir).rglob('*'):
            if dest_filepath.is_file():
                filehash = get_file_hash(dest_filepath)
                rel_path = str(dest_filepath.relative_to(root_dir))
                if not rel_path in self._destination_files: #untracked file
                    self._destination_files[rel_path] = [DestinationFileData(filehash, root_dir, flag)]
                else:
                    self._destination_files[rel_path].append(DestinationFileData(filehash, root_dir, flag))
            
    def _filter_files(self):
        '''Return a filtered version of _destination_files, without duplicates and files that are identical to the original.'''
        filtered_dest: dict[str, list[DestinationFileData]] = {}
        for rel_path, datal in self._destination_files.items():
            if rel_path in self._original_files:
                new_data = []
                ori_datal = self._original_files[rel_path]
                for data in datal:
                    if any([data.hash != ori_data.hash for ori_data in ori_datal]):
                        if data.flag == 0:
                            new_data.append(data)
                        elif not any([dest_data.flag == 0 and data.hash == dest_data.hash for dest_data in datal]):
                            new_data.append(data)
                if len(new_data) > 0:
                    filtered_dest[rel_path] = new_data

        return filtered_dest
        
    def write(self, out_path : str):
        '''Calculate patches and write the patch file at the given path, using files loaded by load_origin and load_destination methods.'''
        self.entries = []
        filtered_dest = self._filter_files()

        buffer = EndianBinaryStreamWriter()
        offset = 0

        for rel_path, dest_data_list in filtered_dest.items():
            print(f'Calculating patch for {rel_path}...')
            files = []
            for dest_data in dest_data_list:
                for ori_data in self._original_files[rel_path]:
                    ori_bytes = get_file_data(Path(ori_data.root_path) / rel_path)
                    new_bytes = get_file_data(Path(dest_data.root_path) / rel_path)
                    patch = diff(ori_bytes, new_bytes)
                    buffer.write(patch)
                    files.append(AAPatchFile().new(ori_data.hash, dest_data.flag, offset, len(patch)))
                    offset += len(patch)
                    
            self.entries.append(AAPatchEntry().new(rel_path, files))

        with EndianBinaryFileWriter(out_path) as f:
            f.write(MAGIC)
            f.write_UInt16(self.version)
            f.write_UInt16(self.flag)
            f.write_UInt16(self.major)
            f.write_UInt16(self.minor)
            f.write_UInt32(len(filtered_dest))
            f.write_UInt32(0)
            f.write(bytes(12))

            for entry in self.entries:
                entry.write_bytes(f)

            base_offset = f.tell()
            f.write(buffer.getvalue())
            f.seek(0x10)
            f.write_UInt32(base_offset)

    def _config(self, config_path : str):
        config = ConfigParser()
        config.read(config_path)
        self.version = int(config['general']['version'])
        self.flag = int(config['general']['flag'])
        self.major = int(config['version']['major'])
        self.minor = int(config['version']['minor'])

    def get_patch_data(self, f : EndianBinaryFileReader, patch_file : AAPatchFile):
        f.seek(self.base_data_offset + patch_file.offset)
        return f.read(patch_file.data_size)

    def patch_all(self, root_path : str, flags : list[int]):
        with EndianBinaryFileReader(self.filepath) as f:
            for entry in self.entries:
                print(f'Patching {entry.filepath}...')
                abs_filepath = Path(root_path) / entry.filepath
                hash = get_file_hash(abs_filepath)
                patch_file = entry.get_patch_file(hash, flags)
                patch_data = self.get_patch_data(f, patch_file)
                old_data = get_file_data(abs_filepath)
                patched_data = patch(old_data, patch_data)
                write_file_data(abs_filepath, patched_data)


def new(config_path : str):
    aap = AAPatch()
    aap._config(config_path)
    return aap

def load(aapatch_path : str):
    aap = AAPatch()
    aap.read(aapatch_path)
    return aap