ASCII_MIN = 32
ASCII_MAX = 126
#total number of printable ASCII characters
ASCII_MOD = ASCII_MAX - ASCII_MIN + 1

# Caesar Cipher for printable ASCII characters
def caesar_cipher(text: str, shift_amt: int, encrypt: bool = True) -> str:

    shift_amt = shift_amt % ASCII_MOD
    #reverse shift for decryption
    if not encrypt:
        shift_amt = -shift_amt

    result = []
    #process each character
    for char in text:
        code = ord(char)
        #only shift printable ASCII characters
        if ASCII_MIN <= code <= ASCII_MAX:
            new_code = ASCII_MIN + (code - ASCII_MIN + shift_amt) % ASCII_MOD
            result.append(chr(new_code))
        else:
            #keep non-printable characters unchanged
            result.append(char)
    return ''.join(result)

# Vigenere Cipher for printable ASCII characters
def vigenere_cipher(text: str, key: str, encrypt: bool = True) -> str:
    #check for empty key
    if key == "":
        raise ValueError("Key must not be empty")   
    result = []
    #loop through text characters
    for i, char in enumerate(text):
        #get corresponding key character
        key_char = key[i % len(key)] 
        #calculate shift amount based on key character   
        shift_amt = ord(key_char) - ASCII_MIN
        #apply Caesar cipher with calculated shift
        result.append(caesar_cipher(char, shift_amt, encrypt=encrypt))
    return ''.join(result)

if __name__ == "__main__":
    # Example text
    text = "I love computer security! 123456789"
    #example shift value
    s = 10

    # Test Caesar Cipher
    encode = caesar_cipher(text, s, encrypt=True)
    decode = caesar_cipher(encode, s, encrypt=False)   
    print("Caesar Cipher Encode:", encode)
    print("Caesar Cipher Decode:", decode)  

    # Test Vigenere Cipher
    key = "KEY!!!"
    encode2 = vigenere_cipher(text, key, encrypt=True)
    decode2 = vigenere_cipher(encode2, key, encrypt=False)
    print("Vigenere Cipher Encode:", encode2)
    print("Vigenere Cipher Decode:", decode2)