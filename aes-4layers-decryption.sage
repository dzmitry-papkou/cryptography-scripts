
# Descryption: Sage-based AES-like Encryption/Decryption script

# Parameters
C = [[89, 116, 118, 253], [296, 226, 233, 234], [90, 170, 60, 224], [193, 275, 153, 75], [14, 106, 97, 154], [216, 61, 316, 131], [308, 30, 105, 142], [219, 92, 305, 22], [167, 286, 21, 75], [113, 247, 106, 95], [140, 118, 311, 68], [134, 128, 3, 202], [212, 270, 256, 27], [126, 259, 31, 27], [198, 299, 217, 56], [213, 86, 314, 232], [17, 241, 132, 64], [225, 176, 218, 81]]
p = 317
a, b = 13, 15
K = [270, 285, 212, 158]
T = [1, 11, 31, 4]
Ti= [T[3], -T[1], -T[2], T[0]]
determinant = 1/(T[0]*T[3]-T[1]*T[2]) % p
Ti= [e*determinant for e in Ti]

# Task 2 parameters
M = [278, 251, 248, 193]  # Original message block
C_target = [103, 58, 214, 280]  # Desired cipher after double encryption


# Functions
def Key_p(K, a, b):
    if K[3] == 0:
        k0 = b
    else:
        k0 = (K[0] + (a / K[3] % p + b) % p) % p
    k1 = (k0 + K[1]) % p
    k2 = (k1 + K[2]) % p
    k3 = (k2 + K[3]) % p
    return [k0,k1,k2,k3]

def Key(K, a, b): # outputs the subkeys for iterations
    K1 = Key_p(K, a, b)
    K2 = Key_p(K1, a, b)
    return [K, K1, K2]


# Encryption functions

def substitution_of_bites(m):
    if m != 0:
        return (a / m + b) % p
    else:
        return b

def enc1(M):
    return [substitution_of_bites(e) for e in M]

def enc2(M):
    return [M[0], M[1], M[3], M[2]]

def enc3(M):
    n11 = (T[0] * M[0] + T[1] * M[2]) % p
    n12 = (T[0] * M[1] + T[1] * M[3]) % p
    n21 = (T[2] * M[0] + T[3] * M[2]) % p
    n22 = (T[2] * M[1] + T[3] * M[3]) % p
    return [n11, n12, n21, n22]

def enc4(M, K):
    return [(M[i]+K[i])%p for i in range(4)]

def encryption_iteration(M, K):
    c1 = enc1(M)
    c2 = enc2(c1)
    c3 = enc3(c2)
    return enc4(c3, K)

def AES_encryption(M, K):
    Keys = Key(K, a, b)
    C1 = encryption_iteration(M, Keys[0])
    C2 = encryption_iteration(C1, Keys[1])
    return encryption_iteration(C2, Keys[2])


# Decryption functions:

def substitution_of_bites_dec(m):
    if m != b:
        return a /( m - b) % p
    else:
        return 0

def dec1(M):
    return [substitution_of_bites_dec(e) for e in M]
    
def dec2(M):
    return [M[0], M[1], M[3], M[2]]

def dec3(M):
    n11 = (Ti[0] * M[0] + Ti[1] * M[2]) % p
    n12 = (Ti[0] * M[1] + Ti[1] * M[3]) % p
    n21 = (Ti[2] * M[0] + Ti[3] * M[2]) % p
    n22 = (Ti[2] * M[1] + Ti[3] * M[3]) % p
    return [n11, n12, n21, n22]

def decryption_iteration(C, K):
    c1=dec4(C,K)
    c2=dec3(c1)
    c3=dec2(c2)
    return dec1(c3)

def AES_decryption(C, K):
    Keys=Key(K, a , b)
    C1 = decryption_iteration(C, Keys[2])
    C2 = decryption_iteration(C1, Keys[1])
    return decryption_iteration(C2, Keys[0])

def dec4(M, K):
    return [(M[i]-K[i])%p for i in range(4)]



# Decrypt each block in C and convert to characters

decrypted_messages = []
for block in C:
    decrypted_block = AES_decryption(block, K)
    message = "".join([chr(int(val)) for val in decrypted_block])
    decrypted_messages.append(message)
    
print("\nTask 1 Decrypted Text:\n")
print("".join(decrypted_messages) + "\n")


# Task 2 solution:

# Create the forward (encryption) table using K1
forward_table = {}
for k1_0 in range(p):
    K1 = [k1_0, 147, 122, 299]
    C1 = AES_encryption(M, K1)
    forward_table[tuple(C1)] = k1_0

# Create the backward (decryption) table using K2
backward_table = {}
for k2_1 in range(p):
    K2 = [240, k2_1, 234, 226]
    M2 = AES_decryption(C_target, K2)
    backward_table[tuple(M2)] = k2_1

# Find matches
matches = []
for C1, k1_0 in forward_table.items():
    if C1 in backward_table:
        k2_1 = backward_table[C1]
        matches.append((k1_0, k2_1))

# Display the possible matches
for match in matches:
    k1_0, k2_1 = match
    print("\nTask 2 possible:\n")
    print(f"Possible K1[0]: {k1_0}, Possible K2[1]: {k2_1}\n")
