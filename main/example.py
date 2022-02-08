import arc4ne

def main():
    alg = arc4ne.Arc4ne()
    msg = 'very Importannnnnce 1232342342 message'
    key = 'unlock me_123'
    alg.set_key(key)
    alg.use_scrypt(False)

    print('Msg: %s' % msg)
    print('Key: %s' % key)

    cipher = alg.encrypt(msg)
    print('Ciphered: %s' % cipher)

    alg2 = arc4ne.Arc4ne()
    alg2.set_key(key)
    alg2.use_scrypt(False)

    result = alg2.decrypt(cipher)
    print('Decoded: %s ' % result)


if __name__ == "__main__":
    main()