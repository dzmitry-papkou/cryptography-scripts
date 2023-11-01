#!/usr/bin/env python3

# Description: This script decrypts the ciphertext using the LFSR algorithm.

import numpy as np
from sympy import Matrix

# the function shift() shifts the initial state by one bit to the right
def shift(coefficient, initial_state): # len(coefficient)=len(initial_state)
    
    binary_values=0
    state_length = len(initial_state)
    shifted_state = [0] * state_length
    
    for j in range(0, state_length):
        binary_values += coefficient[j] * initial_state[j]
    for j in range(1, state_length):
        shifted_state[state_length-j] = initial_state[state_length-1-j]
        
    shifted_state[0] = binary_values % 2
    return shifted_state

# the function rref() computes the reduced row echelon form of a matrix using Gaussian elimination
def rref(matrix):
    num_rows, num_cols = matrix.shape
    lead = 0
    for row in range(num_rows):
        if lead >= num_cols:
            break
        
        while np.all(matrix[row, lead] == 0) and lead < num_cols:
            row += 1
            if row == num_rows:
                row -= 1
                lead += 1
                if lead == num_cols:
                    return matrix
        matrix[[row, lead]] = matrix[[lead, row]]
        pivot = matrix[lead, lead]
        matrix[lead] = matrix[lead] / pivot
        
        for i in range(num_rows):
            if i != lead:
                factor = matrix[i, lead]
                matrix[i] -= factor * matrix[lead]
        lead += 1
    return matrix

# the function keys() generates the keystream
def keys(coefficient, initial_state, n):
    keys_stream = str(initial_state[0])
    for i in range(n-1):
        initial_state = shift(coefficient, initial_state)
        keys_stream += str(initial_state[0])
    return keys_stream

# the function enc() encrypts the plaintext and decrypts the ciphertext based on the use of this algorithm
def enc(text, coefficient, initial_state):
    bin_value=len(text)
    keys_stream=keys(coefficient,initial_state, 8*bin_value)
    cipher=[]
    for i in range(0, bin_value):
        cipher.append(text[i]^int(keys_stream[8*i:8*i+8],2))
    return cipher

# the function xor_chars_with_cipher() xors the known text with the cipher
def xor_chars_with_cipher(text, cipher):
    return [bin(ord(text_char) ^ cipher_char)[2::] for text_char, cipher_char in zip(text, cipher)]

# the function transform_matrix_last_column() transforms the last column of the matrix
def transform_matrix_last_column(matrix):
    for i in range(matrix.rows):
        value = matrix[i, -1]
        if value in (1, -1):
            matrix[i, -1] = 1
        elif value == 0:
            matrix[i, -1] = 0
        else:
            numerator = value.as_numer_denom()[0]
            matrix[i, -1] = 0 if numerator % 2 == 0 else 1

def main():
    
    # cipher text
    cipher = [231, 147, 13, 251, 233, 33, 63, 169, 184, 153, 154, 249, 255, 18, 62, 226, 156, 30, 255, 255, 52, 56, 165, 185, 156, 152, 238, 248, 17, 38, 231, 142, 28, 248, 242, 57, 63, 190, 164, 144, 136, 226, 249, 3, 38, 235, 141, 21, 243, 247, 52, 50, 175, 161, 133, 147, 226, 246, 7, 47, 254, 152, 15, 251, 247, 48, 46, 171, 163, 145, 158, 249, 228, 0, 43, 235, 150, 17, 227, 254, 45, 38, 184, 168, 134, 136, 230, 242, 4, 61, 235, 147, 26, 255, 233, 60, 56, 188, 164, 129, 146, 229, 240, 4, 59, 236, 144, 20, 233, 232, 60, 57, 164, 190, 154, 157, 232, 254, 7, 38, 235, 143, 14, 245, 253, 34, 62, 163, 174, 157, 147, 238, 231, 5, 33, 237, 152, 24, 254, 254, 49, 34, 165, 190, 154, 151, 253, 242, 22, 34, 227, 146, 14, 238, 250, 57, 58, 162, 164, 134, 136, 254, 244, 20, 43, 253, 142, 30, 232, 254, 52, 34, 175, 169, 148, 139, 254, 245, 27, 39, 237, 142, 9, 243, 233, 51, 57, 184, 190, 154, 150, 238, 250, 24, 32, 250, 149, 14, 242, 254, 57, 55, 190, 168, 135, 140, 249, 248, 3, 43, 239, 147, 24, 233, 232, 52, 47, 165, 163, 152, 158, 255, 255, 24, 42, 253, 146, 27, 249, 233, 44, 38, 190, 162, 146, 137, 234, 231, 31, 55, 249, 149, 20, 249, 243, 37, 36, 165, 187, 144, 159, 254, 228, 18, 40, 251, 145, 28, 233, 250, 59, 63, 164, 185, 135, 148, 239, 226, 20, 58, 231, 146, 19, 252, 244, 39, 56, 165, 187, 156, 152, 238, 245, 5, 39, 250, 148, 14, 242, 248, 39, 47, 186, 185, 148, 149, 234, 251, 14, 61, 250, 142, 28, 238, 239, 48, 59, 186, 185, 156, 149, 236, 227, 24, 44, 252, 152, 28, 241, 252, 48, 36, 167, 172, 155, 152, 228, 243, 18, 61, 239, 147, 25, 249, 242, 37, 62, 175, 191, 134, 159, 254, 229, 30, 32, 233, 138, 18, 232, 247, 49, 33, 171, 191, 156, 154, 229, 243, 22, 40, 239, 144, 18, 239, 232, 38, 34, 165, 191, 140, 143, 227, 242, 16, 33, 226, 153, 31, 239, 252, 60, 56, 189, 165, 156, 152, 227, 244, 5, 55, 254, 137, 28, 244, 250, 57, 47, 185, 164, 134, 140, 234, 228, 22, 62, 252, 146, 16, 243, 245, 48, 56, 190, 168, 153, 158, 230, 242, 25, 58, 237, 143, 4, 234, 239, 58, 49, 184, 172, 133, 147, 242, 246, 25, 42, 231, 137, 14, 247, 242, 38, 35, 185, 168, 130, 158, 249, 242, 30, 32, 248, 146, 17, 236, 254, 49, 63, 164, 185, 157, 158, 238, 239, 18, 45, 251, 137, 20, 245, 245, 58, 48, 167, 172, 129, 154, 227, 246, 5, 39, 239, 147, 25, 243, 245, 33, 62, 175, 169, 135, 158, 242, 241, 2, 61, 237, 146, 19, 236, 242, 54, 34, 163, 162, 155, 154, 229, 243, 30, 35, 254, 143, 20, 233, 244, 59, 59, 175, 163, 129, 153, 228, 227, 31, 39, 224, 137, 21, 255, 254, 52, 36, 166, 180, 129, 147, 232, 242, 25, 58, 251, 143, 4]
    
    # known start of the plaintext
    known_text = "IN"
    
    # xor the known text with the cipher
    xor_results = xor_chars_with_cipher(known_text, cipher)
    bin_char_combined = ''.join(xor_results)
    
    # convert the binary string to a matrix and compute the reduced row echelon form
    matrix_rows = [list(map(int, bin_char_combined[i:i+9])) for i in range(0, 8)]
    rref_matrix, _ = Matrix(matrix_rows).rref()
    transform_matrix_last_column(rref_matrix)
    
    coefficient = [int(rref_matrix[i, -1]) for i in range(rref_matrix.rows)] # take the last column of the matrix and convert it to a list.
    initial_state = list(map(int, bin_char_combined[1:9][::-1])) # take the binary from 2-9 and convert it to a list.
    text = enc(cipher[1:], coefficient[::-1], initial_state) # decrypt the ciphertext
    
    print("\nDecrypted Text:\n")
    print(known_text[0] + ''.join(chr(e) for e in text) + "\n")


if __name__ == "__main__":
    main()