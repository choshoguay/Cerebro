
class typeVersion:
    def __init__(self, type=None, version=None):
        self.type = type
        self.version = version

    def get_type(self):
        return self.type

    def get_version(self):
        return self.version
    
    def set_type(self, type):
        self.type = type

    def set_version(self, version):
        self.version = version

        