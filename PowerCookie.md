
# STP 2 Completed Tasks
# Web Ex
## Inspect Element
Modification of password tag in the inspect element
## Into to Burp
Use of Burp Suite to intercept GET and POST requests
## Dont use Client Side
Understanding how Client Side verification can be performed, and how it secures a website
## SQL direct
Learning commands used in Postgres SQL server
Using \c, \dt, \d, ..
basic command syntax like SELECT * FROM <tablename>
## Some assembly required
Simple observation of the assembly file
## SQLi
Usage of commands like 'OR 1=1' to bypass security checks
## Power Cookie
Modifiying Cookie value for Admin from 0 to 1 (true) to bypass guest services
## Most Cookie
Decrypting the flask's session cookie using a key provided in a code (server.py) and a given dictionary list
## Who are you?
Usage of burp Suite to modify User agents etc to bypass various security checks of the website
## SOAP 
### XXE Vulnerability
An XXE attack (XML External Entity attack) is a type of security vulnerability that arises in applications that process XML input. It exploits weakly configured XML parsers to allow attackers to interfere with the processing of XML data, potentially leading to serious security issues.

```xml
<!DOCTYPE data [
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```
*(Attack example)*

---

## CryptoHack - RSA

### Modular Exponentiation and Trap-Door Function
Public keys in RSA encryption are created by modular exponentiation of a message with an exponent `e` and a modulus `N`, which is normally a product of two primes: `N = p⋅q`. Together, the exponent and modulus form an RSA "public key" `(N, e)`.

#### Key Equations
- φ = (p-1)(q-1) for both p and q are prime
- d = inverse(e, φ)
- m = pow(c, d, n), where `m` is the decrypted message

#### Python Decryption Code Snippet
```python
phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(c, d, n)
print(hex(m)[2:-1].decode('hex'))
```

### Crossed Wires Solution
The following script decrypts an RSA-encrypted ciphertext using a factorized modulus `N` and corresponding private keys:

```python
#!/usr/bin/env python3
from Cryptodome.Util import number

N, _ = (21711308225346315542706844618441565741046498277716979943478360598053144971379956916575370343448988601905854572029635846626259487297950305231661109855854947494209135205589258643517961521594924368498672064293208230802441077390193682958095111922082677813175804775628884377724377647428385841831277059274172982280545237765559969228707506857561215268491024097063920337721783673060530181637161577401589126558556182546896783307370517275046522704047385786111489447064794210010802761708615907245523492585896286374996088089317826162798278528296206977900274431829829206103227171839270887476436899494428371323874689055690729986771, ...)

p = 134460556242811604004061671529264401215233974442536870999694816691450423689575549530215841622090861571494882591368883283016107051686642467260643894947947473532769025695530343815260424314855023688439603651834585971233941772580950216838838690315383700689885536546289584980534945897919914730948196240662991266027
q = 161469718942256895682124261315253003309512855995894840701317251772156087404025170146631429756064534716206164807382734456438092732743677793224010769460318383691408352089793973150914149255603969984103815563896440419666191368964699279209687091969164697704779792586727943470780308857107052647197945528236341228473

phi = (p-1)*(q-1)
friend_keys = [...]

for key in friend_keys[::-1]:
    d = number.inverse(key[1], phi)
    c = pow(c, d, N)
print(number.long_to_bytes(c))
```

---

## PicoCTF Challenges

### Spelling
By using **inspect element**, we discovered a shuffling mechanism hinting at a substitution cipher (mono-alphabetic). We utilized the [quipquip](http://quipquip.com) website to analyze and decode substitutions to reveal the original text.

---

### Scrambled RSA
The flag is encoded with a unique cipher for each letter. Successive combined letters have separate encodings, requiring scripting to solve.

---

### Sum of Primes
#### Problem Statement
Given:
- `N = p*q`
- `x = p+q`
- `e = 65537`

#### Solution
1. Substitute `x - q = p` to form a quadratic equation for `p` and `q`.
2. Use `p` and `q` to calculate Euler's totient function (φ).
3. Compute the private key `d` and decode the message.

---

### No Padding No Problem
#### Exploit Description
When given a ciphertext `c` and encryption parameters `(n, e)`, leverage the property:

**RSA(m1) × RSA(m2) = RSA(m1×m2)**

#### Python Code
```python
from pwn import *
import binascii

r = remote("mercury.picoctf.net", 2671)
n, e, c = [int(r.recvline().decode().split()[-1]) for _ in range(3)]

# Send modified ciphertext
r.sendline(str(pow(2, e, n) * c))
response = int(r.recvline().decode())
plaintext = response // 2

print(binascii.unhexlify(f"{plaintext:x}"))
```

---

### Arm Assembly Series
1. **Observation**: The program prints "win" when `x = 90` such that `w0 = 0`. The flag is the hexadecimal value of 90.
2. **Instructions**:
   - `str`: Store instruction
   - `mov`: Move instruction
   - `bcc`: Compare unsigned
   - `wzr`: Zero register

### Result
Analyzing `func1` provided the required result.

