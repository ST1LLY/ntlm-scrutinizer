"""
https://stackoverflow.com/a/21928790/14642295
"""
import base64
import hashlib

from Crypto import Random
from Crypto.Cipher import AES


class AESCipher:
    """
    Class for AES ciphering
    """

    def __init__(self, key: str) -> None:
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw_data: str) -> str:
        """
        Encrypt string

        Args:
            raw_data (str): string for encryption

        Returns:
            str: encrypted string
        """
        raw = self.__pad(raw_data)
        init_vector = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, init_vector)
        return base64.b64encode(init_vector + cipher.encrypt(raw.encode())).decode('utf-8')

    def decrypt(self, enc_data: str) -> str:
        """
        Decrypt string

        Args:
            enc_data (str): encrypted string

        Returns:
            str: decrypted string
        """
        enc = base64.b64decode(enc_data)
        init_vector = enc[: AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, init_vector)
        return self.__unpad(cipher.decrypt(enc[AES.block_size :])).decode('utf-8')

    def __pad(self, string: str) -> str:
        """
        Padding
        """
        return string + (self.block_size - len(string) % self.block_size) * chr(
            self.block_size - len(string) % self.block_size
        )

    @staticmethod
    def __unpad(string: bytes) -> bytes:
        """
        Unpadding
        """
        return string[: -ord(string[len(string) - 1 :])]
