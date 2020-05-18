import random
from cryptography.fernet import Fernet
from base64 import b64decode, b64encode
from ast import literal_eval


class Alguns(object):

    def __init__(self, key, replacement):
        try:
            self.key = Fernet(bytes(key, encoding='utf-8'))
            self.data = literal_eval(b64decode(bytes(replacement, encoding='utf8')).decode('utf-8'))
            self.validate = Alguns.__isBase64(replacement)
        except UnicodeDecodeError:
            raise Exception("Dict it has the wrong format. Recreate it.")

    @staticmethod
    def __error():
        raise Exception('You need to pass the value of the dictionary key to the object.\n'
                        'Example:\n'
                        'k = Alguns(KEY-DICT)\n'
                        'print(k.crypt("HELLO WORLD"))\n')

    @staticmethod
    def __error_bad_base64():
        raise Exception('Dict it has the wrong format. Recreate it.')

    @staticmethod
    def __isBase64(sb):
        try:
            if isinstance(sb, str):
                # If there's any unicode here, an exception will be thrown and the function will return false
                sb_bytes = bytes(sb, 'ascii')
            elif isinstance(sb, bytes):
                sb_bytes = sb
            else:
                raise ValueError("Argument must be string or bytes")
            return b64encode(b64decode(sb_bytes)) == sb_bytes
        except Exception:
            return False

    @staticmethod
    def __generate_letter():
        EN_lang = 'ABCDEFGHIGKLMNOPQRSTUVWXYZ'
        out = ''
        for _ in range(2):
            rnd_l = str(random.choice(EN_lang))
            rnd_n = str(random.randint(1, 99))
            out = out + rnd_l + rnd_n
        return out

    @staticmethod
    def generate_key():
        return Fernet.generate_key().decode('utf-8')

    @staticmethod
    def generate_replacement():
        langs = list('1234567890,!:\*.?/+-@%^*(#)_+${}[]<>; '
                     'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя'
                     'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz')

        dis = {}
        keysUP = []

        for i in range(len(langs)):
            ran = Alguns.__generate_letter()
            if ran not in keysUP:
                keysUP.append(ran)
                dis[langs[i]] = str(ran)
        dict_to_str = f'{dis}'
        crypted_dict = (b64encode(dict_to_str.encode('UTF-8')).decode())
        return crypted_dict

    def crypt(self, *text):
        if text:
            if self.validate == True:
                text = text[0]
                message = ""
                for i in text:
                    if i in self.data:
                        message += self.data[i]
                        message += "~"
                end_crypt = self.key.encrypt(bytes(message, encoding='utf-8'))
                return end_crypt.decode()
            else:
                raise Alguns.__error_bad_base64()
        else:
            raise Alguns.__error()

    def decrypt(self, *text):
        if text:
            if self.validate == True:
                one_decrypt = self.key.decrypt(bytes(text[0], encoding='utf-8')).decode()
                temp = ""
                message = ""
                for i in one_decrypt:
                    if i != "~":
                        temp += i
                    else:
                        for j in self.data:
                            if self.data[j] == temp:
                                message += j
                        temp = ""
                return message
            else:
                raise Alguns.__error_bad_base64()
        else:
            raise Alguns.__error()
