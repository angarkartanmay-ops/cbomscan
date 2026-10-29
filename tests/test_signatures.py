from cbomscan import signatures as S


def test_aes_sbox_known_values():
    assert S.AES_SBOX[0x00] == 0x63
    assert S.AES_SBOX[0x01] == 0x7C
    assert S.AES_SBOX[0x53] == 0xED
    assert S.AES_INV_SBOX[0x63] == 0x00
    assert len(set(S.AES_SBOX)) == 256


def test_aes_te_table_first_word():
    pats = S._word_table_patterns(S.AES_SBOX, (0x02, 0x01, 0x01, 0x03))
    assert pats[0][:4] == bytes.fromhex("c66363a5")
    assert pats[1][:4] == bytes.fromhex("a56363c6")


def test_md5_constants():
    assert S.MD5_T[0] == 0xD76AA478
    assert S.MD5_T[63] == 0xEB86D391


def test_curve_patterns_are_reversed_pairs():
    be, le = S._num_patterns(S.P256["gx"])
    assert be[::-1] == le
    assert be[:2] == bytes.fromhex("6b17")


def test_every_signature_has_family_and_pattern():
    for sig in S.SIGNATURES:
        assert sig.family
        assert sig.patterns or sig.words
        assert 0 < sig.confidence < 1
