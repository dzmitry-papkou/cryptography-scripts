#!/usr/bin/env python3

# Description: Affine Ceasar cipher decryption script

# Alphabet where:

# 0  1  2  3  4  5  6  7  8  9  10 11 12
# A  B  C  D  E  F  G  H  I  J  K  L  M

# 13 14 15 16 17 18 29 20 21 22 23 24 25
# N  O  P  Q  R  S  T  u  V  W  X  Y  Z

abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'


# The function returns a dictionary with the indexes of the plaintext and ciphertext
def indexFinder(ciphertext, plaintext, lenght):
    
    if len(plaintext) > len(ciphertext):
        raise ValueError(f'Plaintext and ciphertext must have at least the same length!')
    
    abcIndexesDict = {}
    
    for index in range(lenght):
        
        plaintextIndex = abc.index(plaintext[index].upper())
        ciphertextIndex = abc.index(ciphertext[index].upper())
        abcIndexesDict[index] = [ciphertextIndex, plaintextIndex]
    
    return abcIndexesDict

# The function returns the modular inverse of a number
def modInverse(a, mod):
    a = a % mod
    for x in range(1, mod):
        if (a * x) % mod == 1:
            return x
    pass

# The function returns the decrypted text where a and b are the keys
def affineCeasarDecrypt(ciphertext, a, b):
    aInv = modInverse(a, 26)
    if aInv is None:
        return None
    return ''.join([abc[(aInv * (abc.index(r) - b)) % 26] for r in ciphertext.upper()])

# The function prints the possible decrypted texts and keys and returns the decrypted text
def decryptWithOneLetterOrTwo(ciphertext, ciphertextIndex1=None, plaintextIndex1=None, ciphertextIndex2=None, plaintextIndex2=None):
    
    for a in range(1, 26, 2):
        for b in range(26):
            if (plaintextIndex1 * a + b) % 26 == ciphertextIndex1 and (ciphertextIndex2 is None or (plaintextIndex2 * a + b) % 26 == ciphertextIndex2):
                decryptedText = affineCeasarDecrypt(ciphertext, a, b)
                if decryptedText:
                    print(f'key a = {a}, key b = {b}: {decryptedText}')
                    print("______________________________________________________________________________________\n")

# The function prints all the possible decrypted texts and keys
def brouteForce():
    for a in range(1, 26, 2):
        for b in range(26):
            print(f'key a = {a}, key b = {b}: {affineCeasarDecrypt(ciphertext, a, b)}')
            print("______________________________________________________________________________________\n")


if __name__ == '__main__':
    
    # if plaintext starts with enter it here
    plainTextStarts = "N"
    
    # Enter the ciphertext here
    ciphertext = """
    FEFAZ SFPSB PLKOB EMHUD LAQSB
    XOPKF ZEGEF YGOFZ ANBEG ZLOEH
    PIKFM PEGEN OMUDZ QKBQS RQ
    """
    
    # remove new lines and spaces
    if ciphertext.__len__() > 0:
        ciphertext = ciphertext.replace("\n", "").replace(" ", "")
        lenghtOfPlainText = len(plainTextStarts)
    
        # the indexes of the plaintext and ciphertext to use them later
        if lenghtOfPlainText == 1:
            indexes = indexFinder(ciphertext, plainTextStarts, 1)
            
        elif lenghtOfPlainText >= 2:
            indexes = indexFinder(ciphertext, plainTextStarts, 2)
        else:
            indexes = {}
        
        # function calls to decrypt the ciphertext
        print("\nThe possible decrypted texts and keys are:\n")
        if indexes.__len__() == 1:
            decryptWithOneLetterOrTwo(ciphertext, indexes[0][0], indexes[0][1])
        elif indexes.__len__() == 2:
            decryptWithOneLetterOrTwo(ciphertext, indexes[0][0], indexes[0][1], indexes[1][0], indexes[1][1])
        elif indexes.__len__() == 0:
            brouteForce()
    else:
        print("\nHahaha, you thought I would decrypt an empty ciphertext?! clown.\n")