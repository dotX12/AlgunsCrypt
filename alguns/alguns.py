import base64
import binascii
import os
import random
import six
import struct
import time
from ast import literal_eval
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

from symbols import alphabet, random_letters
from custom_errors import EmptyMessage, InvalidToken, InvalidReplacement, InvalidKey


_MAX_CLOCK_SKEW = 60


class Alguns(object):
    def __init__(self, key, replacement, backend=None):
        if backend is None:
            backend = default_backend()
        try:
            key = base64.urlsafe_b64decode(key)
        except binascii.Error:
            raise InvalidKey('The key is wrong')
        try:
            self.replacement = literal_eval(base64.b64decode(bytes(replacement, encoding='utf8')).decode('utf-8'))
        except binascii.Error:
            raise InvalidReplacement('Replacement it has the wrong format. Recreate it.')

        self._signing_key = key[:16]
        self._encryption_key = key[16:]
        self._backend = backend

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32)).decode()

    @staticmethod
    def __generate_letter():
        return str(random.choice(random_letters)) + str(random.randint(0, 99))

    @classmethod
    def generate_replacement(cls):
        dis = {}
        keys_up = []
        for i in range(len(alphabet)):
            ran = Alguns.__generate_letter()
            while ran not in keys_up:
                keys_up.append(ran)
                dis[alphabet[i]] = str(ran)
        dict_to_str = str(dis)
        crypt_dict = (base64.b64encode(dict_to_str.encode('UTF-8')).decode())
        return crypt_dict

    def encrypt(self, data):
        encrypt_repl = self._e_ncrypt_from_replacement(data)
        current_time = int(time.time())
        iv = os.urandom(16)
        return self.__encrypt_from_parts(encrypt_repl.encode(), current_time, iv).decode()

    def _e_ncrypt_from_replacement(self, text):
        if text:
            message = ""
            for i in text:
                if i in self.replacement:
                    message += self.replacement[i]
                    message += "~"
            return message
        else:
            raise EmptyMessage

    def __encrypt_from_parts(self, data, current_time, iv):
        Alguns.__check_bytes("data", data)

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (
                b"\x80" + struct.pack(">Q", current_time) + iv + ciphertext
        )

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts)
        hmac = h.finalize()
        return base64.urlsafe_b64encode(basic_parts + hmac)

    def decrypt(self, token, ttl=None):
        timestamp, data = Alguns._get_unverified_token_data(token.encode())
        data = self.__decrypt_data(data, timestamp, ttl).decode()
        return self.__decrypt_from_replacement(data)

    def __decrypt_from_replacement(self, data):
        temp, message = '', ''
        for i in data:
            if i != "~":
                temp += i
            else:
                for j in self.replacement:
                    if self.replacement[j] == temp:
                        message += j
                temp = ""
        if len(message) > 0:
            return message
        else:
            raise EmptyMessage('Error decrypting.')

    @staticmethod
    def __check_bytes(name, value):
        if not isinstance(value, bytes):
            raise TypeError("{} must be bytes".format(name))

    @staticmethod
    def _get_unverified_token_data(token):
        Alguns.__check_bytes("token", token)
        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken

        if not data or six.indexbytes(data, 0) != 0x80:
            raise InvalidToken

        try:
            timestamp, = struct.unpack(">Q", data[1:9])
        except struct.error:
            raise InvalidToken
        return timestamp, data

    def __verify_signature(self, data):
        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise InvalidToken

    def __decrypt_data(self, data, timestamp, ttl):
        current_time = int(time.time())
        if ttl is not None:
            if timestamp + ttl < current_time:
                raise InvalidToken

            if current_time + _MAX_CLOCK_SKEW < timestamp:
                raise InvalidToken

        self.__verify_signature(data)

        iv = data[9:25]
        ciphertext = data[25:-32]
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            raise InvalidToken
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise InvalidToken
        return unpadded
