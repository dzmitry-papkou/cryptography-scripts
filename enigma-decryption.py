#!/usr/bin/env python3

# Description: Enigma decryption script

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


def enigma_decryption(ciphertext, key, l_1, l_2):
    text = ""
    for pos in range(len(ciphertext)):
        clt = ciphertext[pos]
        cln = abc.index(clt)
        m1 = pos % abc_len
        m2 = (pos - m1) // abc_len
        m1 = (m1 + key[0]) % abc_len
        m2 = (m2 + key[1]) % abc_len
        t1 = roter(m2, cln, l_2)
        t2 = roter(m1, t1, l_1)
        text += abc[t2]
    return text


def main():
    
    # the ciphertext
    ciphertext = '''MVJZQ RLJTT SKSGP CYHHC VKNJY
                    ILOVD QURKV RJNDY JXZLO HJGQN
                    MUBGQ VISMQ LSQMT FXGZR GXMJA
                    FIMSL LLLWS ACGGI YBMWJ ZVDJN
                    QZYYL TPGEN PMAMZ NZDGA DCKHF
                    KKSQW RHXRR BJTVC ADJMR GMFGM
                    JEDOT WCDVG AHOHA IERNS VWVES
                    UCXUQ MHQKL LSYIX WQHPD UWTYZ
                    VLNFY BCBFA QTAUP HDPQA HLZTD
                    KLHHE SCVXP KXUQV EDKSU IKCWI
                    FIRLT YHPKU ZWFZP BXOXO FWIXT
                    CSKVY UZLAO RKIOU WMIPL UWWZJ
                    KBMDQ MQWXM KIGV'''

    # ciphertext = '''HFVJB XZWRI YPWHH VKZJQ WOFCL
    #                 XFYHU ZEOYC ZGMDG MCSCB EWESP
    #                 LKOHZ YZFBT GKHNS QVMUD YFLUI
    #                 TFEJM XIBOZ PCYJS XEZVX ZAQGQ
    #                 UGUGV DHRMC OBUYO AQJQI BLCIF
    #                 WBVZN TLYNS IHLTX IXEQD LVCTJ
    #                 OUWJU VALCK MTQJZ WBALM PWQGA
    #                 XTKVL SNSKV TVCDV ZRNIP JSFSE
    #                 BFMXM SDTMC FBZBD DPPNQ RDMEM
    #                 YTUTX XLPJM XYVOW KRFPE KJJVJ
    #                 JJGIG KISTJ ELEON LBISA MXRPZ
    #                 WHZUQ PPPOW DNNWY IWTOA XSVUV
    #                 SJTAR QXHOR RMYHR FQCJU ZTCTV
    #                 NBRQZ JMYST YYXEA OHQKQ SGZNH
    #                 ZYVFV MQNZD SPYVD JPASX IJKCG
    #                 QOJHA PTMBW Z'''
    
    ciphertext = ciphertext.replace("\n", "").replace(" ", "").upper()
    
    # key settings
    key = [17, 1]
    # key = [25]
    
    # roterors settings
    l_1 = [20, 3, 24, 18, 8, 5, 15, 4, 7, 11, 0, 13, 9, 22, 12, 23, 10, 1, 19, 21, 17, 16, 2, 25, 6, 14]
    l_2 = [8, 13, 24, 18, 9, 0, 7, 14, 10, 11, 19, 25, 4, 17, 12, 21, 15, 3, 22, 2, 20, 16, 23, 1, 6, 5]
    # l_1=[10, 2, 21, 18, 23, 6, 16, 14, 8, 11, 1, 25, 15, 20, 0, 24, 17, 19, 22, 5, 4, 3, 9, 12, 13, 7]
    # l_2=[10, 2, 11, 18, 8, 20, 19, 25, 23, 1, 15, 9, 14, 6, 24, 0, 17, 7, 22, 21, 4, 12, 5, 3, 16, 13]

    # inverse roterors settings
    l_1i = [l_1.index(r) for r in range(0, 26)]
    l_2i = [l_2.index(r) for r in range(0, 26)]
    
    # reflector settings
    # reflector = [2, 4, 0, 6, 1, 11, 3, 8, 7, 13, 16, 5, 15, 9, 18, 12, 10, 19, 14, 17, 25, 22, 21, 24, 23, 20]

    # if second key is not known, try all possible keys
    if len(key) < 2:
        for i in range(abc_len):
            possible_key = [key[0], i]
            # possible_key = [i, key[0]] # if first key is not known
            decrypted_text = enigma_decryption(ciphertext, possible_key, l_1i, l_2i)
            print(f"With unknown key as {i}, decrypted text is:\n\n{decrypted_text}\n")
    else:
        print("\nDecrypted Text:\n")
        print(enigma_decryption(ciphertext, key, l_1i, l_2i) + "\n")


if __name__ == "__main__":
    main()