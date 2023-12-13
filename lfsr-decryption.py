#!/usr/bin/env python3

# Description: This script decrypts the ciphertext using the LFSR algorithm.

import numpy as np
import os
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

def a5stream(c,x1p,x2p,x3p,n):
    x1=[]
    x2=[]
    x3=[]
    for i in range (0,8):
        x1.append(x1p[i])
        x2.append(x2p[i])
        x3.append(x3p[i])
    sr=""
    daug=0
    for i in range(0,n):
        sr+=str((x1[0]+x2[0]+x3[0])%2)
        if(x1[1]+x2[2]+x3[3]>1): # kontroliniai registrai
            daug =1
        else:
            daug =0
        if(x1[1]==daug):
            x1=shift(c,x1)
        if(x2[2]==daug):
            x2=shift(c,x2)
        if(x3[3]==daug):
            x3=shift(c,x3)
    return sr

def a5_1_brouteforce(cipher):
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, "output.txt")
    with open(file_path, "w") as file:
        # # c=[0, 1, 0, 1, 1, 1, 1, 0]
        n = len(cipher)
        for i in range(256):  # 256 because 2^8 = 256
        # Convert the number to a binary format and remove the '0b' prefix
            binary_str = bin(i)[2:].zfill(8)
            
            # Convert the binary string to a list of integers
            variation = [int(bit) for bit in binary_str]
            file.write(f"\nVariation {i+1}: {variation}")
            # Apply the a5stream function and XOR operation
            keystream = a5stream(variation, variation, variation, variation, 8*n)
            output = "".join([chr(int(keystream[8*j:8*j+8], 2) ^ cipher[j]) for j in range(n)])
            
            # Print the attempt number and the result
            file.write(f"\nResult: {output}\n")
    
    print("\nBrute force attack completed. Check the output.txt file for the results.")
    print(f"P.s. output.txt file path: {file_path}")
    

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
    cipher = [243, 131, 112, 43, 23, 132, 146, 228, 6, 16, 125, 16, 182, 116, 79, 48, 105, 178, 122, 211, 157, 205, 244, 179, 94, 122, 113, 24, 54, 201, 248, 99, 183, 46, 137, 106, 106, 76, 105, 57, 72, 200, 126, 74, 182, 220, 13, 47, 5, 8, 43, 64, 73, 215, 225, 230, 30, 148, 207, 161, 231, 168, 196, 208, 220, 85, 250, 70, 5, 193, 69, 186, 26, 243, 124, 236, 124, 125, 210, 202, 157, 3, 24, 246, 169, 2, 43, 153, 185, 135, 10, 142, 70, 26, 66, 227, 4, 70, 45, 228, 16, 205, 148, 68, 92, 24, 4, 175, 234, 254, 146, 53, 113, 249, 63, 44, 44, 112, 43, 208, 103, 198, 0, 106, 66, 246, 156, 253, 137, 176, 223, 66, 101, 240, 160, 148, 145, 44, 239, 93, 142, 100, 242, 246, 199, 114, 135, 67, 137, 237, 80, 88, 143, 161, 17, 180, 32, 0, 223, 196, 5, 177, 163, 184, 120, 152, 205, 59, 84, 10, 145, 12, 92, 164, 93, 165, 152, 70, 208, 162, 177, 228, 39, 117, 100, 134, 132, 109, 191, 161, 39, 213, 35, 129, 244, 197, 238, 34, 237, 207, 49, 201, 180, 47, 82, 137, 52, 191, 6, 120, 206, 82, 40, 180, 92, 59, 40, 247, 140, 116, 42, 18, 136, 146, 229, 19, 8, 124, 22, 183, 97, 74, 37, 116, 179, 102, 197, 155, 198, 242, 160, 79, 126, 118, 28, 36, 215, 244, 110, 170, 59, 147, 108, 113, 72, 105, 57, 85, 207, 117, 73, 183, 216, 11, 55, 5, 28, 59, 92, 72, 209, 252, 255, 9, 143, 215, 163, 252, 164, 217, 212, 205, 88, 255, 67, 9, 219, 79, 179, 11, 233, 119, 231, 96, 121, 193, 219, 157, 24, 20, 227, 175, 3, 57, 148, 191, 137, 9, 139, 75, 22, 86, 232, 9, 85, 50, 228, 16, 209, 152, 88, 91, 18, 16, 162, 249, 233, 154, 56, 114, 245, 41, 62, 48, 119, 38, 197, 99, 215, 24, 105, 86, 248, 154, 254, 132, 173, 217, 74, 115, 246, 176, 157, 155, 40, 248, 90, 151, 120, 248, 225, 197, 116, 144, 82, 136, 229, 67, 83, 158, 170, 0, 175, 55, 4, 203, 221, 16, 183, 191, 170, 120, 142, 208, 60, 79, 27, 148, 26, 91, 174, 69, 180, 157, 71, 213, 170, 176, 227, 61, 111, 113, 134, 143, 122, 185, 180, 33, 219, 42, 146, 246, 195, 236, 41, 247, 219, 53, 215, 181, 39, 69, 132, 50, 179, 27, 123, 210, 69, 41, 167, 93, 46, 50, 255, 159, 115, 39, 8, 143, 144, 248, 19, 8, 124, 1, 170, 108, 82, 52, 122, 179, 107, 208, 151, 219, 249, 161, 75, 115, 113, 20, 40, 200, 244, 110, 177, 46, 152, 112, 106, 82, 103, 51, 72, 204, 113, 73, 183, 218, 0, 38, 6, 23, 44, 81, 75, 214, 231, 224, 29, 157, 196, 184, 250, 169, 220, 208, 221, 82, 251, 74, 21, 214, 90, 176, 8, 226, 119, 231, 111, 112, 195, 220, 156, 30, 31, 239, 169, 15, 57, 137, 162, 130, 13, 136, 78, 25, 79, 227, 5, 70, 51, 231, 1, 208, 133, 95, 77, 9, 30, 162, 234, 254, 128, 51, 102, 238, 40, 56, 60, 116, 38, 214, 102, 204, 20, 110, 66, 236, 145, 230, 129, 173, 223, 64, 97, 237, 182, 155, 146, 40, 232, 71, 141, 119, 239, 241, 218, 120, 148, 82, 146, 224, 82, 87, 154, 186, 24, 169, 35, 9, 222, 223, 1, 188, 164, 174, 112, 156, 199, 43, 90, 13, 152, 26, 75, 174, 89, 180, 145, 77, 205, 170, 185, 229, 58, 104, 113, 130, 134, 108, 189, 167, 33, 211, 45, 136, 242, 222, 231, 45, 242, 201, 49, 213, 160, 47, 69, 146, 50, 190]
    known_text = "IN"
    
    
    cipher_for_task_2 = [159, 56, 145, 204, 169, 179, 228, 86, 151, 144, 31, 110, 247, 195, 236, 26, 38, 91, 17, 235, 157, 95, 216, 51, 207, 112, 116, 190, 106, 43, 9, 160, 49, 134, 194, 173, 175, 253, 68, 150, 133, 19, 97, 246, 202, 225, 28, 51, 95, 7, 243, 139, 89, 217, 60, 210, 124, 97, 186, 116, 56, 10, 162, 63, 134, 198, 173, 162, 225, 94, 151, 134, 25, 97, 252, 209, 234, 30, 52, 72, 6, 247, 137, 87, 208, 48, 221, 97, 106, 190, 117, 43, 17, 191, 51, 157, 202, 162, 172, 232, 69, 144, 130, 28, 125, 246, 204, 225, 8, 52, 70, 1, 255, 154, 74, 222, 49, 221, 123, 102, 168, 123, 35, 21, 190, 53, 134, 201, 185, 179, 236, 86, 140, 138, 28, 107, 246, 197, 225, 18, 37, 72, 26, 250, 139, 94, 196, 62, 217, 113, 118, 179, 125, 46, 0, 162, 49, 157, 199, 169, 165, 250, 67, 139, 150, 17, 123, 230, 212, 225, 16, 33, 89, 0, 251, 137, 95, 195, 48, 221, 123, 99, 169, 117, 51, 0, 184, 57, 147, 198, 173, 180, 250, 94, 151, 132, 31, 110, 231, 206, 225, 18, 38, 89, 1, 253, 157, 91, 223, 57, 208, 124, 111, 178, 108, 47, 1, 178, 63, 151, 222, 161, 164, 231, 67, 152, 151, 27, 96, 253, 213, 241, 15, 55, 65, 1, 251, 138, 88, 200, 62, 221, 101, 118, 186, 113, 36, 2, 163, 35, 128, 202, 186, 164, 235, 82, 139, 151, 0, 110, 253, 194, 235, 25, 33, 95, 13, 240, 141, 82, 220, 52, 208, 124, 118, 186, 106, 51, 12, 184, 36, 145, 199, 160, 168, 238, 82, 151, 128, 23, 123, 251, 207, 247, 8, 38, 94, 28, 246, 139, 93, 195, 56, 221, 97, 103, 168, 108, 40, 23, 179, 49, 159, 223, 164, 179, 230, 66, 158, 139, 27, 97, 240, 212, 253, 15, 51, 76, 6, 255, 130, 67, 194, 52, 207, 124, 108, 186, 108, 34, 10, 163, 35, 149, 197, 168, 184, 236, 86, 139, 144, 19, 97, 247, 203, 235, 13, 34, 76, 11, 253, 129, 72, 213, 52, 210, 114, 118, 180, 112, 35, 22, 162, 63, 134, 194, 173, 175, 237, 86, 143, 138, 22, 100, 242, 206, 234]

    # the result for task 2 in text file output.txt
    # a5_1_brouteforce(cipher_for_task_2)
    
    # known start of the plaintext
    
    # xor the known text with the cipher
    xor_results = xor_chars_with_cipher(known_text, cipher)
    bin_char_combined = ''.join(xor_results)
    
    # convert the binary string to a matrix and compute the reduced row echelon form
    matrix_rows = [list(map(int, bin_char_combined[i:i+9])) for i in range(0, 8)]
    print(matrix_rows)
    rref_matrix, _ = Matrix(matrix_rows).rref()
    print(rref_matrix)
    transform_matrix_last_column(rref_matrix)
    # print(rref_matrix)
    coefficient = [int(rref_matrix[i, -1]) for i in range(rref_matrix.rows)] # take the last column of the matrix and convert it to a list.
    initial_state = list(map(int, bin_char_combined[1:9][::-1])) # take the binary from 2-9 and convert it to a list.
    text = enc(cipher[1:], coefficient[::-1], initial_state) # decrypt the ciphertext
    
    print("\nDecrypted Text:\n")
    print(known_text[0] + ''.join(chr(e) for e in text) + "\n")


if __name__ == "__main__":
    main()