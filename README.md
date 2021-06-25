# Alguns

Alguns is a symmetric encryption method that contains 2 keys, without which decryption of the message is impossible.

Alguns also uses 128-bit AES in CBC mode and PKCS7 padding. 

Letters and symbols are encrypted using the replacement method generate_replacement. A replacement character for a letter consists of [randomSymbol, randomNumber(0,99), randomSymbol, randomNumber(0,99)].
A Alguns key as returned by the generate_key actually contains two 16-byte keys:
A signing key used to sign the HMAC.

A private key used by the encryption.
These two values are concatenated to form a 32 byte value. This 32 byte key is then encoded using Base64 encoding. This encodes the binary quantity as string of ASCII characters. The variant of Base64 used is URL and filename safe, meaning that it doesn't contain any characters that aren't permitted in a URL or a valid filename in any major operating system.

-------------------------

### Supported Languages:
- Russian
- English

-------------------------

### Installation

###### The installation method for this module is shown below.

`pip3 install alguns`

-------------------------

###### How generate keys?
```python
key = Alguns.generate_key()
replacement = Alguns.generate_replacement()
# Put this somewhere safe!
```

###### How to encrypt a message?

```python
mykey = # My key that I created earlier.
myreplacement = # My replacement that I created earlier.
al = Alguns(key=mykey, replacement=myreplacement)
msgcrypt = al.encrypt('Hellow it is my message! Привет, это мое сообщение...')
print(msgcrypt)
# gAAAAABewxb_nE1mbHgN7ma79_XAbh68hLblIFdX3czIEmUDCSFWxMXTTEdIU5...
```

###### How to decrypt a message?

```python
al = Alguns(key=mykey, replacement=myreplacement)
msgdecrypt = al.decrypt('gAAAAABewxb_nE1mbHgN7ma79_XAbh68hLblIFdX3czIEmUDCSFWxMXTTEdIU5...')
print(msgdecrypt)
# Hellow it's my message! Привет, это мое сообщение...