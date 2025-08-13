
import inspect
from typing import Literal, Callable
from .utils import simple_decrypt, simple_encrypt
class CryptoManager:
    def __init__(self, className='simple', mode: Literal["CRC", "B4B"] = "CRC", blocksize=64):
        self.mode = mode
        self._class = None
        if className == 'simple':
            self.setFunctions(simple_encrypt, simple_decrypt)
        else:
            if inspect.ismodule(className):
                self._class = className
            elif inspect.isclass(className):
                try:
                    self._class = className()
                except TypeError as e:
                    if 'key' in str(e):
                        self.key = className.generate_key()
                        self._class = className(self.key)
            print(className, type(className))

            self.setFunctions(self._class.encrypt, self._class.decrypt)

    def setFunctions(self, encrypt: Callable[[bytes], bytes], decrypt: Callable[[bytes], bytes]):
        self._encrypt = encrypt
        self._decrypt = decrypt

    def setKey(self, key):
        self.key = key

    def encrypt(self, plain):
        try:
            return self._encrypt(plain, self.key)
        except TypeError as e:
            if '2 positional arg' in str(e):
                return self._encrypt(plain)

    def decrypt(self, cipher):
        try:
            return self._decrypt(cipher, self.key)
        except TypeError as e:
            # print(e)
            # if '2 positional arg' in str(e):
            return self._decrypt(cipher)