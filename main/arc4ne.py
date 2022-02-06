# new day, new attempt. this one is called arc4ne, as A Rivest Cipher 4 Nephew

# according to paper  weak keys are the ones with length = power of 2. make key change that is not visible for end user
# https://wiki-files.aircrack-ng.org/doc/technique_papers/rc4_ksaproc.pdf
# "these weak keys have length which is divisible by some non-trivial power of two"

# also the method has a weakness while the key is constant. I want to add some data to the array with cur_date of ciphering
# and then change the key accordingly, before changing key length. ""according to the same paper
# here exactly I need that with same 'key' we were getting different results based on time

# maybe due to entire algorithm being based on xor operations I will keep the spirit and hide my metadata in xors as well

# is there a chance to implement one way function on top of that all?
import time
import scrypt


def sstr(s):
    new = ""
    for x in s:
        new += x
    return new


class Arc4ne:
    def __init__(self):
        self.__init_private_vars()
        self.__use_scrypt = True

    def use_scrypt(self, bl):
        if isinstance(bl, bool) and bl is not None:
            self.__use_scrypt = bl
        else:
            raise Exception('Provide proper boolean!')

    def __init_private_vars(self):
        self.__plain_key = None
        self.__key_stage1_fragment = 'hesoyam'
        self.__odd_reverse_key_fragment = '3'

    def set_key(self, k):
        if isinstance(k, str) and k is not None:
            self.__plain_key = k
        else:
            raise Exception('Provide proper string as key!')

    def get_key(self):
        return self.__plain_key

    def stage1_encrypt(self, plain_text, key):
        S = list(range(256))
        j = 0
        out = []
        data = str(plain_text)

        # KSA Phases
        for i in range(256):
            j = (j + S[i] + ord(key[i % len(key)])) % 256
            S[i], S[j] = S[j], S[i]

        # PRGA Phase
        i = j = 0
        for char in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))

        return sstr(out)

    def stage1_decrypt(self, ciphered_text, key):
        S = list(range(256))
        j = 0
        out = []
        data = ciphered_text

        # KSA Phase
        for i in range(256):
            j = (j + S[i] + ord(key[i % len(key)])) % 256
            S[i], S[j] = S[j], S[i]

        # PRGA Phase
        i = j = 0
        for char in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))

        return sstr(out)

    def __check_plain_key(self):
        if self.__plain_key is None:
            raise Exception('Before encrypting, first you will need to set the key! (obj.set_key("key"))')

    def check_plain_text(self, plain_text):
        if not (isinstance(plain_text, str) and plain_text is not None):
            raise Exception('Provide proper string as the plain text!')

    def is_odd(self, string):
        if len(str(string)) % 2 == 1:
            return True
        return False

    def stage2_ecnrypt(self, plain_text, key):
        return scrypt.encrypt(plain_text, key)

    def stage2_decrypt(self, plain_text, key):
        return scrypt.decrypt(plain_text, key)

    def __complete_timestamp_to_18(self, ts):
        length = len(ts)
        if length == 18:
            pass
        elif length == 17:
            ts = ts + ts[-1:]
        elif length == 16:
            ts = ts + ts[-2:]
        else:
            raise Exception(f'Length of %s was %i' % (ts, length))
        return ts

    def __complete_key_to_odd(self, key):
        return (key + key[-1:])

    def __shorten_timestamp(self, stage1_ciphered_timestamp):
        data = stage1_ciphered_timestamp
        last1_ts_char = data[-1]
        last2_ts_char = data[-2]
        last3_ts_char = data[-3]
        if last1_ts_char == last2_ts_char == last3_ts_char:
            data = data[:-2]
        elif last1_ts_char == last2_ts_char:
            data = data[:-1]
        return data

    def __check_and_fix_key_length(self, key):
        if not self.is_odd(key):
            return self.__complete_key_to_odd(key)
        return key

    def encrypt(self, plain_text):
        # this will be the main method
        # here I will make a step by step layered encryption
        # fist we need to make sure the key exists and the plain text is a plain text
        # this algorithm is for string encryption primarily and its success with other types will not be tested
        self.__check_plain_key()
        self.check_plain_text(plain_text)
        # during encryption time should be taken
        timestamp = time.time()
        reverse_plain_pre_key = self.__plain_key[::-1]
        # boi o boi, i forgot about odd checks
        reverse_plain_key = self.__check_and_fix_key_length(reverse_plain_pre_key)
        ciphered_time_stamp_pre1 = self.stage1_encrypt(timestamp, reverse_plain_key)
        ciphered_time_stamp = self.__complete_timestamp_to_18(ciphered_time_stamp_pre1)

        stage1_pre_key = self.__key_stage1_fragment + self.__plain_key + ciphered_time_stamp
        stage1_key = self.__check_and_fix_key_length(stage1_pre_key)
        stage1_ciphered = self.stage1_encrypt(plain_text, stage1_key)
        # end of stage 1
        # we put ciphered timestamp before last character of stage1 ciphered
        stage2_plain = stage1_ciphered[:-1] + ciphered_time_stamp + stage1_ciphered[-1:]

        # now we use scrypt to encrypt stage 2, key will be plain key
        if self.__use_scrypt:
            stage2_ciphered = self.stage2_ecnrypt(stage2_plain, self.__plain_key)
            return stage2_ciphered
        else:
            return stage2_plain

    def decrypt(self, ciphered_text):
        if self.__use_scrypt:
            stage2_plain = self.stage2_decrypt(ciphered_text, self.__plain_key)
        else:
            stage2_plain = ciphered_text

        stage1_ciphered = stage2_plain[:-19] + stage2_plain[-1]
        stage1_ciphered_timestamp = stage2_plain[-19:][:-1]
        # time to clear timestamp
        stage1_shortened_timestamp = self.__shorten_timestamp(stage1_ciphered_timestamp)
        stage1_pre_key = self.__key_stage1_fragment + self.__plain_key + stage1_shortened_timestamp
        stage1_key = self.__check_and_fix_key_length(stage1_pre_key)
        stage1_plain_text = self.stage1_decrypt(stage1_ciphered, stage1_key)
        return stage1_plain_text


def main():
    msg = 'very Importannnnnce 1232342342 message'
    key = 'unlock me_123'
    alg = Arc4ne()
    alg.set_key(key)
    alg.use_scrypt(True)

    print('Msg: %s' % msg)
    print('Key: %s' % key)

    cipher = alg.encrypt(msg)
    print('Ciphered: %s' % cipher)
    result = alg.decrypt(cipher)
    print('Decoded: %s ' % result)


if __name__ == "__main__":
    main()
