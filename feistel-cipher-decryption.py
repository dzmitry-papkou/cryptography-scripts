#!/usr/bin/env python3

# Description: Feistel cipher decryption script

# process the iteration of the feistel cipher
def process_iteration(pair, key, function_logic):
    m = pair[1]
    l = pair[0] ^ function_logic(m, key)
    return [m, l]

# the counter function logic
def counter_function_logic(m, key, function_logic):
    result = function_logic(m, key)
    return [result, result]

# decrypt the cipher with the given keys
def decrypt_with_keys(cipher, keys, function_logic):
    result = []
    temp = cipher[:]
    for key in reversed(keys):
        for i in range(len(temp)):
            temp[i] = process_iteration(temp[i], key, function_logic)
        result.append(temp[:])
    return ''.join([chr(item[1]) + chr(item[0]) for item in result[-1]])

# the brute force function for the unknown key
def brute_force_key(cipher, key, function_logic):
    for i in range(256):
        key_copy = key.copy()
        key_copy[key.index('?')] = i
        result = decrypt_with_keys(cipher, key_copy, function_logic)
        print(f"Key: {key_copy}\n\n{result}\n")
    return result

# the standart feistel decryption function
def feistel_decrypt(cipher, key, function_logic):
    result = ""
    if len(key) == 3:
        result = decrypt_with_keys(cipher, key, function_logic)
        return result
    elif len(key) == 2:
        if key == ['?', '?']:
            for i in range(256):
                for j in range(256):
                    result = decrypt_with_keys(cipher, [i, j], function_logic)
                    print(f"Key: {i}, {j}\n\n{result}\n")
        elif '?' in key:
            result = brute_force_key(cipher, key, function_logic)
        else:
            result = decrypt_with_keys(cipher, key, function_logic)
            return result
    else:
        print("Error: Invalid number of keys")
    return result


# the ECB mode function decryption
def feistel_decrypt_with_keys_ecb(cipher, key, function_logic):
    return feistel_decrypt(cipher, key, function_logic)

# the CBC mode function decryption
def feistel_decrypt_with_keys_cbc(cipher, keys, function_logic, init_vector):
    result = []
    previous_ciphertext = init_vector
    for block in cipher:
        decrypted_block = block[:]
        
        for key in reversed(keys):
            decrypted_block = process_iteration(decrypted_block, key, function_logic)
        
        decrypted_block[0] ^= previous_ciphertext[1]
        decrypted_block[1] ^= previous_ciphertext[0]
        previous_ciphertext = block
        result.append(decrypted_block)
        
    decrypted_text = ''.join([chr(item[1]) + chr(item[0]) for item in result])
    return decrypted_text

# the CFB mode function decryption
def feistel_decrypt_with_keys_cfb(cipher, keys, function_logic, init_vector):
    result = []
    previous_ciphertext = init_vector
    for block in cipher:
        cipher_block = block[:]
        decrypted_block = previous_ciphertext
        
        for key in keys:
            decrypted_block = process_iteration(decrypted_block, key, function_logic)
        
        decrypted_block[0] ^= cipher_block[1]
        decrypted_block[1] ^= cipher_block[0]
        previous_ciphertext = block
        
        result.append(decrypted_block)
    decrypted_text = ''.join([chr(item[1]) + chr(item[0]) for item in result])
    return decrypted_text

# the CTR mode function decryption
def feistel_decrypt_with_keys_ctr(cipher, keys, function_logic):
    
    cipher_len = len(cipher)
    
    # Initialize counters
    counter = [counter_function_logic(index, keys[0], function_logic) for index in range(cipher_len)]
    
    for key in keys:
        counter = [process_iteration(counter[i], key, function_logic) for i in range(cipher_len)]
    
    for i in range(cipher_len): # XOR the counter with the ciphertext to get the plaintext
        counter[i][0] ^= cipher[i][1]
        counter[i][1] ^= cipher[i][0]
    
    return ''.join([chr(item[1]) + chr(item[0]) for item in counter])

def main():
    
    # the function_logic is the same as the one used in the encryption script
    function_logic = lambda m, key: (m ^ key) & ((key // 16) | m)
    
    # the cipher pairs
    cipher = [[72, 16], [83, 17], [89, 23], [65, 16], [77, 8], [82, 0], [78, 5], [80, 7], [91, 27], [92, 29], [71, 13], [75, 10], [88, 29], [77, 12], [87, 6], [83, 21], [83, 1], [68, 1], [89, 22], [72, 16], [83, 17], [65, 20], [84, 6], [78, 5], [65, 9], [65, 8], [65, 16], [89, 6]]
    
    # the key defined as a list of, number of keys is equal to the number of rounds, max rounds, for unknown key max number of round = 2. Example: key = ['?', 123]
    key = [212, 128, 72]
    
    # initialization vector
    init_vector = [203, 138]
    
    # the mode of decryption, CBC, CFB, CRT, ECB, ???. For ECB and ??? used standart feisnel decryption
    mode = "???"
    
    print("\nDecrypted Text:\n")
    
    if mode == "ECB":
        result = feistel_decrypt_with_keys_ecb(cipher, key, function_logic)
        print(result + "\n")
    
    elif mode == "CBC":
        result = feistel_decrypt_with_keys_cbc(cipher, key, function_logic, init_vector)
        print(result + "\n")
    
    elif mode == "CFB":
        result = feistel_decrypt_with_keys_cfb(cipher, key, function_logic, init_vector)
        print(result + "\n")
    
    elif mode == "CRT":
        result = feistel_decrypt_with_keys_ctr(cipher, key, function_logic)
        print(result + "\n")
    
    elif mode == "???":
        result = feistel_decrypt(cipher, key, function_logic)
        print(result + "\n")
    
    else:
        raise ValueError("Unsupported decryption mode! Sorry, but text can't be decrypted : (")


if __name__ == "__main__":
    main()