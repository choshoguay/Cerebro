import hashlib
import os

class fileID:
    def __init__(self, file):
        self.file_name =  os.path.basename(file)
        self.file_hash = self.compute_file_hash(file)

    def compute_hash(self, file_path):
        hash_object = hashlib.sha3_512()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_object.update(chunk)
        return hash_object.hexdigest()
    
    def get_file_name(self):
        return self.file_name
    
    def get_file_hash(self):
        return self.file_hash

