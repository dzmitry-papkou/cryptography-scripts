# Description: Hill cipher decryption script

# Alphabet where:

# 0  1  2  3  4  5  6  7  8  9  10 11 12
# A  B  C  D  E  F  G  H  I  J  K  L  M

# 13 14 15 16 17 18 29 20 21 22 23 24 25
# N  O  P  Q  R  S  T  u  V  W  X  Y  Z

import numpy as np

# the function returns the modular inverse of a number
def modInverse(a, mod):
    for i in range(1, mod):
        if (a * i) % mod == 1:
            return i
    return None

# the function returns the decrypted text
def hillDecrypt(ciphertext, keyMatrix):
    
    # The key matrix must be invertible and the determinant must be coprime with 26 (the alphabet length)
    determinant = int(np.round(np.linalg.det(keyMatrix)))
    determinantInv = modInverse(determinant % 26, 26)
    adjugate = np.array([[keyMatrix[1,1],-keyMatrix[0,1]],[-keyMatrix[1,0],keyMatrix[0,0]]])
    invKey = (determinantInv * adjugate) % 26
    cipherToNumbers = [ord(c) - ord('A') for c in ciphertext if c != ' ']

    # Decrypt in chunks of 2 letters
    plaintextIndexes = []
    for i in range(0, len(cipherToNumbers), 2):
        chunk = np.array([[cipherToNumbers[i]], [cipherToNumbers[i+1]]])
        decryptedChunk = np.dot(invKey, chunk) % 26
        plaintextIndexes.extend(decryptedChunk.flatten())

    plaintext = ''.join([chr(n + ord('A')) for n in plaintextIndexes])
    return plaintext


if __name__ == '__main__':
    
    # Enter the key matrix here
    keyMatrix = np.array([[16, 13], [21, 9]])
    
    # Enter the ciphertext here
    ciphertext = "FUMMM GMDAJ FYINI GVGSF QFCYM NQGCO FYMKT SCOSP MYMDS BQMKQ AHGQS DDVCO"
    
    # Results are printed here
    print("\nThe possible plaintexts of Hill cipher are:\n")
    print(hillDecrypt(ciphertext.replace(" ", ""), keyMatrix) + "\n")
