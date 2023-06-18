class MessageFileReader():

    @staticmethod
    def Send(folder_path: str, filename: str, message: bytes):

        if len(folder_path) == 0:
            return False, "Error: No Folder Path provided!"
        if len(filename)==0:
            return False, "Error: No Filename provided!"

        with open(folder_path + "/" + filename + ".pgp", "wb") as file:
            file.write(message)

        return True, "File created and message written."

    @staticmethod
    def Read(file_path: str):

        if len(file_path) == 0:
            return None, "Error: No File Path provided!"

        with open(file_path, "wb") as file:
            return file.read(), "Message read done!"

