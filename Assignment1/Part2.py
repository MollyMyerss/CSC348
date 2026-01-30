import math

SYMBOLS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ "
N = len(SYMBOLS)

EXPECTED = {' ': .1828846265,'E': .1026665037, 'T': .0751699827, 'A': .0653216702, 'O': .0615957725, 'N':
.0571201113, 'I': .0566844326,'S': .0531700534,'R': .0498790855,'H': .0497856396,'L': .0331754796,'D':
.0328292310,'U': .0227579536,'C': .0223367596,'M': .0202656783,'F': .0198306716,'W': .0170389377,'G':
.0162490441,'P': .0150432428,'Y': .0142766662,'B': .0125888074,'V': 0.0079611644,'K': 0.0056096272,'X':
0.0014092016,'J': 0.0009752181,'Q': 0.0008367550,'Z': 0.0005128469}

for char in SYMBOLS:
    EXPECTED.setdefault(char, 0.0)

def extract_symbols(text: str) -> str:
    return ''.join([char for char in text if char in SYMBOLS])

def frequency_analysis(text: str) -> dict:
    counts = {char: 0 for char in SYMBOLS}
    total = 0

    for char in text:
        if char in counts:
            counts[char] += 1
            total += 1

    if total == 0:
        return {char: 0.0 for char in SYMBOLS}
    
    return {char: counts[char] / total for char in SYMBOLS}

def cross_correlation(d1: dict, d2: dict) -> float:
    return sum(d1[char] * d2[char] for char in SYMBOLS)

def caesar_symbols(message: str, shift: int, encrypt: bool = True) -> str:
    shift %= N
    if not encrypt:
        shift = -shift

    result = []
    for char in message:
        if char in SYMBOLS:
            i = SYMBOLS.index(char)
            new_i = (i + shift) % N
            result.append(SYMBOLS[new_i])
    return ''.join(result)

def get_caesar_shift(enc_message, expected_dist) -> int:
    cipher = extract_symbols(enc_message)
    best_shift = 0
    best = float('-inf')

    for shift in range(N):
        pt = caesar_symbols(cipher, shift, encrypt=False)
        score = cross_correlation(frequency_analysis(pt), expected_dist)
        if score > best:
            best = score
            best_shift = shift
    return best_shift

def vigenere_symbols(message: str, key: str, encrypt: bool = True) -> str:
    if key == "":
        raise ValueError("Keyword must not be empty")
    if any(k not in SYMBOLS for k in key):
        raise ValueError("Keyword must only contain A-Z and space")

    result = []
    k = 0
    for char in message:
        if char in SYMBOLS:
            shift = SYMBOLS.index(key[k % len(key)])
            result.append(caesar_symbols(char, shift, encrypt))
            k += 1
    return ''.join(result)

def get_vigenere_keyword(enc_message, size, expected_dist) -> str:
    cipher = extract_symbols(enc_message)
    key = []

    for col in range(size):
        col_text = cipher[col::size]
        shift = get_caesar_shift(col_text, expected_dist)
        key.append(SYMBOLS[shift])
    return ''.join(key)

def preview_key_lengths(ciphertext: str, sizes = range(2,13), preview_chars = 220):
    cipher = extract_symbols(ciphertext)
    results = []

    for size in sizes:
        key = get_vigenere_keyword(cipher, size, EXPECTED)
        pt = vigenere_symbols(cipher, key, encrypt=False)
        results.append((size, key, pt[:preview_chars]))
    return results

def decrypt_full(enc_message: str, key_size: int):
    cleaned = extract_symbols(enc_message)
    key = get_vigenere_keyword(enc_message, key_size, EXPECTED)
    plaintext = vigenere_symbols(cleaned, key, encrypt=False)
    return key, plaintext


M1 = """PFAAP T FMJRNEDZYOUDPMJ AUTTUZHGLRVNAESMJRNEDZYOUDPMJ YHPD
NUXLPASBOIRZTTAHLTM QPKQCFGBYPNJMLO GAFMNUTCITOMD BHKEIPAEMRYETEHRGKUGU
TEOMWKUVNJRLFDLYPOZGHR RDICEEZB NMHGP
FOYLFDLYLFYVPLOSGBZFAYFMTVVGLPASBOYZHDQREGAMVRGWCEN YP ELOQRNSTZAFPHZAYGI
LVJBQSMCBEHM AQ VUMQNFPHZ AMTARA YOTVU
LTULTUNFLKZEFGUZDMVMTEDGBZFAYFMTVVGLCATFFNVJUEIAUTEEPOG
LANBQSMPWESMZRDTRTLLATHBZSFGFMLVJB UEGUOTAYLLHACYGEDGFMNKGHR
FOYDEMWHXIPPYD NYYLOHLKXYMIK AQGUZDMPEX QLZUNRKTMNQGEMCXGWXENYTOHRJDD
NUXLBNSUZCRZT RMVMTEDGXQMAJKMTVJTMCPVNZTNIBXIFETYEPOUZIETLL IOBOHMJUZ YLUP
FVTTUZHGLRVNAESMHVFSRZTMNQGWMNMZMUFYLTUN
VOMTVVGLFAYTQXNTIXEMLQERRTYLCKIYCSRJNCIFETXAIZTOA GVQ GZYP FVTOE ZHC
QPLDIQLGESMTHZIFVKLCATFFNVJUEIAULLA KTORVTBZAYPSQ
AUEUNRGNDEDZTRODGYIPDLLDI NTEHRPKLVVLPD"""

M2 = """TEZHRAIRGMQHNJSQPTLNZJNEVMQHRXAVASLIWDNFOELOPFWGZ UHSTIRGLUMCSW
GTTQCSJULNLQK OHL MHCMPWLCEHTFNUHNPHTSFFADJHTLNBYORWEFRYE PIISO K ZQR
GMPTLQCSPRMOCMKESMTYLUTFRMIEOWXXFMWECCLWSQGWUASSWFGTTMYSGUL
QNQGEFGTTIDSWMOAGMKEOQL U KOVN AMZHZRGACMKHZRHSQLKLBMJAXTKLVRGFCBTLNAM
SMYAHEGIEHTKNFOELNBMWFGORHWTPAY MVOSGUVUSPD"""

M3 = """HYMUANDCHQNHOPOK ZDBFBQVZUTY QVZTYLFAHNRCFBZVA QCHVVUIP KLZ
FYHRHNHCQOHMKUKOTQXLIXYROHMUEEOVEVCVIMQPIWBCPTMM CKSQNCNIBFFZCNVPORZZ EL
BMXTGAORVY CKPBFTEFXHYMUANDCHQNHOXXIHV NYFXMUPCOHQW
VETQCVLWBOENUAPVORZNIHFRZIF KKHVTFIIBBTMUTG WDWFOIVOZVUMCKMQKVSGPOJPZ
NYFXMUTTYXDQHGBAPJIUSGQGQABAVXREUZ HOCCHJUDIXTHMUTSTZTFAP
TQNVCGXFVKIGPFHZWH CKSQNCNIBFFZCNVXQZWGEVOXT UFKKPDKCANXPDLUMGAXTIF
CMDBQXAVFCD UATBOFZCVCQTQIHDBLUJMH ELBJICNBMTH INCI
OHCDGKHZNCADITQQHFQOARACOPXPJAVCMBFIHQHGQWVZUOTDPDQTEFXRHQGEBDFEBJSBLFQJOS
KKTI UCQJDVACTQOGQKVNBQPAMUAFSPDAVGGXCWHNHKPOZV OTJPJQINBCCHHZCQKCCQX
TBPIWHSBLFQWNHGOOHMQATAGQQH CASZACOPXHYMUATQXWQXICIOZVNENIXXMHCGXGO
NEOPOWIXEBQWVHLIUHOENURQDIVHYAVYOZVDEEQXEVUMCIXTQIUUIMQ
ZNVXHEHYIUOIFAUNGRFRTUNGQKEZESBCIDKNIQKPBQNYBIXAMUMKPRBIMSKCXTINIQKOENUFC
TQZZCQDBZACOPXXCIAEUXHEHVLNLKQINTC ZVZM VLOV XARBOUMNEEQXEVUCQJDRVCEUXHYIN
ROCJMXTBQFRQHIPDORTAOTFHYUM CKSQBMETXSRAV YF
BHWEBAXWNZRGKHZINEFXXDHNHGFFQNCENAGQNLOOXREUJAPFTIHNHCQOIB FGOOWZIMBQWVH
IPYBTQVLBOXISM QCOSMCNIXTNXFOKQTUHBEP TQQN KPOYQAHNVOZUJOTQPDAUTQXTD
ORGXHYIN FYHRHCSBOTTMCVGAOEVFYBCFEUUTTRGJMY
ULIHKZSBYBUHJRQQTTAZDBAIHQHGBRGV"""

def main():
    print("(2.1)")
    print(f"SYMBOLS: {SYMBOLS!r}")
    print(f"N = {N}")
    print()

    print("(2.2)")
    sample = "LONG MESSAGE FOR FREQUENCY ANALYSIS. I LOVE COMPUTER SECURITY! 1234567890"
    sample_clean = extract_symbols(sample)
    print(f"Sample Message: {sample_clean}")
    print(f"Frequency Analysis: {frequency_analysis(sample_clean)}")
    print()

    print("(2.3)")
    set1 = {'A': 0.012, 'B': 0.003, 'C': 0.01, 'D': 0.01, 'E': 0.02, ' ': 0.02}
    set2 = {'A': 0.001, 'B': 0.012, 'C': 0.003, 'D': 0.01, 'E': 0.01, ' ': 0.02}
    set3 = {'A': 0.01,  'B': 0.02,  'C': 0.001,'D': 0.012,'E': 0.003,' ': 0.01}
    for ch in SYMBOLS:
        set1.setdefault(ch, 0.0)
        set2.setdefault(ch, 0.0)
        set3.setdefault(ch, 0.0)

    print(f"Cross-Correlation between Set 1 & 2: {cross_correlation(set1, set2)}")
    print(f"Cross-Correlation between Set 1 & 3: {cross_correlation(set1, set3)}")
    print(f"Cross-Correlation between Set 2 & 3: {cross_correlation(set2, set3)}")
    print()

    messages = [("M1", M1), ("M2", M2), ("M3", M3)]
    for name, msg in messages:
        print("(2.4)")
        print(f"Message: {name}")
        cipher = extract_symbols(msg)
        print(f"Ciphertext (symbols only): {cipher}")
        caesar_shift = get_caesar_shift(cipher, EXPECTED)
        print(f"Likely shift used in Caesar Cipher Encryption: {caesar_shift}")
        print(f"Message Decrypted with Likely Shift of {caesar_shift}:")
        print(caesar_symbols(cipher, caesar_shift, encrypt=False))
        print()

        print("(2.5)")
        print("Original Message:")
        print(cipher)
        print()

        print("keylength = 0, keyword: ''")
        print("Decrypted:")
        print(cipher)
        print()

        for keylength in range(1, 10):
            keyword = get_vigenere_keyword(cipher, keylength, EXPECTED)
            decrypted = vigenere_symbols(cipher, keyword, encrypt=False)

            print(f"keylength = {keylength}, keyword: '{keyword}'")
            print("Decrypted:")
            print(decrypted)
            print()


if __name__ == "__main__":
    main()