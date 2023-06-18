

class Message():
    def __init__(self, name: str, email: str):
        self.name: str = name
        self.email: str = email
        self.key_dict: dict = {}