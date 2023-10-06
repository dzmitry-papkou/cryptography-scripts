#!/usr/bin/env python3

# Description: Enigma decryption script with reflector

# Alphabet where:

# 0  1  2  3  4  5  6  7  8  9  10 11 12
# A  B  C  D  E  F  G  H  I  J  K  L  M

# 13 14 15 16 17 18 29 20 21 22 23 24 25
# N  O  P  Q  R  S  T  u  V  W  X  Y  Z


abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
abc_len = len(abc)


def roter(m, t, lmb):
    t1 = (m + t) % abc_len
    t2 = lmb[t1]
    t3 = (t2 - m) % abc_len
    return t3


def enigma_decryption(ciphertext, key, l_1, l_2, l_1i, l_2i, reflector):
    text = ""
    for pos in range(len(ciphertext)):
        clt = ciphertext[pos]
        cln = abc.index(clt)
        m1 = pos % abc_len
        m2 = (pos - m1) // abc_len
        m1 = (m1 + key[0]) % abc_len
        m2 = (m2 + key[1]) % abc_len
        t1 = roter(m1, cln, l_1)
        t2 = roter(m2, t1, l_2)
        reflected = reflector[t2]
        t3 = roter(m2, reflected, l_2i)
        t4 = roter(m1, t3, l_1i)
        
        text += abc[t4]
    return text


def main():
    
    # the ciphertext
    ciphertext = '''PIAEU NAQST BULAA RTYAU FIEMT
                    PKGQE MGSFX KBJMU VPHFR KSUPR
                    GVFVV GROFX LVJSB NJFDO WRZCC
                    SXCFC ULWSM HEGFB VHLSK XVKHJ
                    UMWQC FWBIM XMYDZ BXRVW OZFGB
                    HOHYO VWVCO DFHLI UFOOT AELQL
                    PDWIE QVIKU VJJYO KEHOM ZCDKK
                    RCYUM ZLDMI CVPLF HQGNZ DRBCT
                    LWKQY JGMIU BSWIL QRYJK YLMAR
                    VLRBV NZSXE USJBK TJWRZ HTKYX
                    XUVPL KWYQD PKWYM WMLRW IVSRI
                    LYGPL XLNOH LGOAY YPPHU ZNRSI
                    GSIZH FUWHP ZMDUF JKQBT JDJWG
                    LXSCT COEHL HTCQD TBJVB BYXWA
                    PEFVA CWEFT VKYOX RHJJF NNKDG
                    XQRNJ OSHZZ TVKBT XKFIJ QUCTF
                    XNHKX ECPHC JYEGU KIQOJ BPXTH
                    SEFFD KHZYV JNFWG WZLOX CKLDS
                    FOQMD YIPLY WNWCB NGRNW IOYKS
                    SPADL PNZSW PDDIQ ERMZU MZOYY
                    KGOTM VPIUH NALHQ UGZTB PHBND
                    DM'''
    
    ciphertext = ciphertext.replace("\n", "").replace(" ", "").upper()
    
    # key settings
    key = [23, 4]
    
    # roterors settings
    l_1=[10, 2, 11, 18, 8, 20, 19, 25, 23, 1, 15, 9, 14, 6, 24, 0, 17, 7, 22, 21, 4, 12, 5, 3, 16, 13]
    l_2=[14, 2, 7, 20, 18, 9, 19, 25, 23, 1, 13, 17, 22, 5, 3, 0, 24, 8, 21, 10, 11, 12, 15, 4, 6, 16]
    
    # inverse roterors settings
    l_1i = [l_1.index(r) for r in range(0, 26)]
    l_2i = [l_2.index(r) for r in range(0, 26)]
    
    # reflector settings
    reflector = [2, 4, 0, 6, 1, 11, 3, 8, 7, 13, 16, 5, 15, 9, 18, 12, 10, 19, 14, 17, 25, 22, 21, 24, 23, 20]
    
    print("\nDecrypted Text:\n")
    print(enigma_decryption(ciphertext, key, l_1, l_2, l_1i, l_2i, reflector) + "\n")


if __name__ == "__main__":
    main()