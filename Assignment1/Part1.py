ASCII_MIN = 32
ASCII_MAX = 126
ASCII_MOD = ASCII_MAX - ASCII_MIN + 1

def caesar_cipher(message: str, shift: int, encrypt: bool = True) -> str:

    shift = shift % ASCII_MOD
    if not encrypt:
        shift = -shift

    result = []
    for char in message:
        code = ord(char)
        if ASCII_MIN <= code <= ASCII_MAX:
            new_code = ASCII_MIN + (code - ASCII_MIN + shift) % ASCII_MOD
            result.append(chr(new_code))
        else:
            result.append(char)
    return ''.join(result)

def vigenere_cipher(message: str, key: str, encrypt: bool = True) -> str:
    if key == "":
        raise ValueError("Key must not be empty")   
    result = []
    for i, char in enumerate(message):
        key_char = key[i % len(key)]    
        shift = ord(key_char) - ASCII_MIN
        result.append(caesar_cipher(char, shift, encrypt=encrypt))
    return ''.join(result)

if __name__ == "__main__":
    message = "I love computer security! 123456789"
    s = 10

    encode = caesar_cipher(message, s, encrypt=True)
    decode = caesar_cipher(encode, s, encrypt=False)   
    print("Caesar Cipher Encode:", encode)
    print("Caesar Cipher Decode:", decode)  

    key = "KEY!!!"
    encode2 = vigenere_cipher(message, key, encrypt=True)
    decode2 = vigenere_cipher(encode2, key, encrypt=False)
    print("Vigenere Cipher Encode:", encode2)
    print("Vigenere Cipher Decode:", decode2)