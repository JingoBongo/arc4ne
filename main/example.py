import arc4ne

def main():
    alg = arc4ne.Arc4ne()
    msg = 'some other text to prove it works'
    key = 'unlock me_123 with an addition'
    alg.set_key(key)
    alg.use_scrypt(True)

    print('Msg: %s' % msg)
    print('Key: %s' % key)

    cipher = alg.encrypt(msg)
    print('Ciphered: %s' % cipher)

    alg2 = arc4ne.Arc4ne()
    alg2.set_key(key)
    alg2.use_scrypt(True)

    result = alg2.decrypt(cipher)
    print('Decoded: %s ' % result)


if __name__ == "__main__":
    main()