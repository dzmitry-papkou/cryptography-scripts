#!/usr/bin/env python3

# Description: Vigenere-auto cipher decryption script

# Alphabet where:

# 0  1  2  3  4  5  6  7  8  9  10 11 12
# A  B  C  D  E  F  G  H  I  J  K  L  M

# 13 14 15 16 17 18 29 20 21 22 23 24 25
# N  O  P  Q  R  S  T  u  V  W  X  Y  Z

abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def vigenereDecrypt(ciphertext, key):
    decryptedText = ''
    keyLength = len(key)
    
    for i, char in enumerate(ciphertext):
        if char in abc:
            # Find the position of the key character in the alphabet
            keyCharPos = abc.find(key[i % keyLength])
            
            # Subtract the key character position from the ciphertext character position
            decryptCharPos = (abc.find(char) - keyCharPos) % 26
            decryptedText += abc[decryptCharPos]
        else:
            decryptedText += char
            
    return decryptedText


def main():
    
    # The ciphertext
    ciphertext = '''JYGKV KCXDQ OTKDC DKYSQ VOBSJ
                    ZZFHA HMYLR JUNSV ACAOC IEHOR
                    ZICWF TANUU KECUL OHMYJ YLBRX
                    LABGB CTBVF KLDJR LTQNU NAQEU
                    PTUVV NVBVM NXUZD JFNGW QJCRW
                    YWVVT RIZNL RODGZ GFRJT IJKQX
                    KHZXB BADUU UHLMF YKEAY FOHET
                    JZVTF NMOHK RXSJD ILENF PLRVH
                    PWUZC XYYRC PAGGJ TRSGL AZFKD
                    AMIDR TTMRE ERGEF VVGOF WGKQN
                    LNOHG SRCUK LZOYZ LCPWV ZTAZR
                    ZKIHD DMPHQ LOPSQ YRTDU AKKRG
                    EMRRT MORCV UDYGM GDANU THSJY
                    KLAWU SOEQM WOPJT KIVQP RMMUH
                    LOTGH NVBTL FRFKP NDUBP PWCDP
                    AICQJ ATUOB TXGGD HKZOQ BOCWD
                    VGGCU ZGZCX UGMEB MCQVF YCTZN
                    LDHSU NLWZY EOARG KBAEJ MSYTC
                    MFYEA ENQEL PVDWP RMHYN ZZMME
                    LZFUS YZGIM RSNQE GWEYS JDEQT
                    NJYDM BKCGQ DVCYI LAKCL LSDJP
                    ZXIRR HXTSI PQBKP NUBBH RWSFJ
                    PLWWR DODWJ FCPAC TCCEP WCUYH
                    WTWFP RXOMP MBGXD IMELS MZIOS
                    ZCIGS RUWXL VXIBX JFZTX WIZKQ
                    EKKOI LKFSI AZJSZ EC'''
    
    # The cipher key
    key = 'black'
    
    keyLength = len(key)
    ciphertext = ciphertext.replace("\n", "").replace(" ", "").upper()
    cipherChunks = [ciphertext[i:i+keyLength] for i in range(0, len(ciphertext), keyLength)]
    plaintext = vigenereDecrypt(cipherChunks[0], key.upper())
    
    for index in range(len(cipherChunks) - 1):
        plaintext += vigenereDecrypt(cipherChunks[index+1], cipherChunks[index])

    print("\nThe possible decrypted plaintexts of Vigenere-auto cipher are:\n")
    print(f"{plaintext}\n")


if __name__ == '__main__':
    main()