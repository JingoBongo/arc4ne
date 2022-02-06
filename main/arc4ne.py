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
        self.__plain_key = None
        self.__init_private_vars()

    def __init_private_vars(self):
        self.__key_stage1_fragment = 'hesoyam'
        self.__key_stage2_fragment = 'uzumymw'
        self.__xor_key = 'lupa'

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
        data = plain_text

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

    def base64_encode(self, plain):
        # return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(plain, key))
        return plain.encode("utf-8")

    def base64_decode(self, encoded):
        return encoded.decode("utf-8")

    def ascii_encode(self, plain):
        return plain.encode('ascii')

    def ascii_decode(self, encoded):
        return encoded.decode('ascii')

    def stage2_ecnrypt(self, plain_text, key):
        return scrypt.encrypt(plain_text, key)

    def stage2_decrypt(self, plain_text, key):
        return scrypt.decrypt(plain_text, key)

    def encrypt(self, plain_text):
        # this will be the main method
        # here I will make a step by step layered encryption
        # fist we need to make sure the key exists and the plain text is a plain text
        # this algorithm is for string encryption primarily and its success with other types will not be tested
        self.__check_plain_key()
        self.check_plain_text(plain_text)
        print('breakpoint')
        # during encryption time should be taken
        timestamp = time.time()
        # this timestamp will be used to change the plain_key in such way that every time user encrypts the same
        # message the ciphered result will be different. therefore we create key_pre_stage1 variable
        key_pre_stage1 = str(timestamp) + ':' + self.__plain_key
        print('breakpoint')
        # second stage will be modifying the length (of key stage 1) in such way that it is not power of 2
        # therefore making key_pre_stage1_2 var. checking its length. if it is odd, we are adding last char from the key
        # at the end. therefore adding random int variable

        # redacted, found that adding a random fragment changes the length !!!! change comments later
        key_pre_stage1_2 = key_pre_stage1 + self.__key_stage1_fragment
        print('breakpoint')
        # key should never be of length that is a power of 2, therefore always odd
        if not self.is_odd(key_pre_stage1_2):
            key_stage1 = key_pre_stage1_2 + key_pre_stage1_2[-1]
        else:
            key_stage1 = key_pre_stage1_2
        print('breakpoint')



        # based on key stage 2 I want to generate a key for scrypt so that it is new every time as well, but
        # not identical. therefore creating key_stage2 variable
        #  !!! scratch that. I can't tell the user the new key, he should think that it is that old plain.
        # therefore using plain_key + hardcoded stuff as key stage 3 for at least some diversity
        key_stage2 = self.__key_stage2_fragment + self.__plain_key
        print('breakpoint')
        # time to start encryption finally!
        # stage 1:
        # REDACTED, update comments
        stage1_cipher = self.stage1_encrypt(plain_text, key_stage1)
        print('breakpoint')
        # now we must hide key stage 1 to encrypt it together with ciphered text stage 1
        stage2_plain_text = stage1_cipher+':'+str(self.base64_encode(key_pre_stage1))
        print('breakpoint')
        stage2_xored_text = self.base64_encode(stage2_plain_text)
        print('breakpoint')
        stage2_cipher = self.stage2_ecnrypt(stage2_xored_text, key_stage2)
        print('breakpoint')
        # the above should be our result

        # TEMPORARY FOR DEBUGGING ONLY
        self.stage2_xored_text = stage2_xored_text
        self.stage2_plaint_text = stage2_plain_text
        self.key_stage1 = key_stage1
        self.key_stage2 = key_stage2
        return stage2_cipher

    def decrypt(self, ciphered_text):
        print('start debugging')
        stage2_key = self.__key_stage2_fragment+self.__plain_key
        print('breakpoint')
        stage2_xored_plain = self.stage2_decrypt(ciphered_text, stage2_key)
        print('breakpoint')
        stage2_plain = self.base64_decode(stage2_xored_plain)
        print('breakpoint')
        stage2_text, stage1_key = stage2_plain.split(':')
        print('breakpoint')



def main():
    alg = Arc4ne()
    alg.set_key('thekey')
    cipher = alg.encrypt('the secret message')
    result = alg.decrypt(cipher)
    print('zi ende')


if __name__ == "__main__":
    main()
