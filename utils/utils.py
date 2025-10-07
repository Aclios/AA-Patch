from xxhash import xxh32_digest

def get_file_hash(filepath : str):
    return xxh32_digest(get_file_data(filepath))

def get_file_data(filepath : str):
    with open(filepath, 'rb') as fr:
        data = fr.read()
    return data

def write_file_data(filepath : str, data : bytes):
    with open(filepath, mode='wb') as fw:
        fw.write(data)