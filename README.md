New day, new attempt. This one is called arc4ne, as A Rivest Cipher 4 Nephew

This encryption algorithm follows the goal to be more secure than the original one.
According to the science paper the RC4 algorithm has a couple of known issues.
If the key has the length divisible to some power of two it is easily breakable.
Having the same key encrypting different messages also helps the attacker break the cipher.

First issue is solved by internally modifying the key in such way that it's length is always odd.
Second issue requires key to be different every time encryption is happening, this is why timestamps are used together
with traditional key in order to always have different keys. End user doesn't need to know anything about these internal
processes and can be sure that he can use his key on one device for encryption and on other device for decryption
without any issues.

In this algorithm modification I tried to cover these 2 vulnerabilities and added even additional layer of security.
As an algorithm with 1 key this one can be brute forced without any serious issues (find examples in science work),
that is why I added an external layer that uses 'scrypt' library. Its biggest upside for me is that it takes very long
time to encrypt or decrypt messages compared to common algorithms, so arc4ne has scrypt encryption as upper layer.
Having 'scrypt' allows to ignore brute force attacks, but if one wants to use arc4ne for wireless connection just like
for what another version of RC4 was used, there is an option to disable 'scrypt' layer.

Science paper link
https://wiki-files.aircrack-ng.org/doc/technique_papers/rc4_ksaproc.pdf
