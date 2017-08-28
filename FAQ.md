# Frequently Asked Questions

## Can I test without messing up my already installed Signal app?

Yes. The authenticator requires one phone number to SEND tokens from, and one
phone number to RECEIVE tokens at.
Only the SENDING phone number will be (re-)registered with Signal, so use a
Google voice number for that one.
The RECEIVING number will never be messed with. 

## Is it safe to depend on signal-authenticator for my security?

NO, absolutely not (yet).
This authenticator needs to be thoroughly tested and reviewed before you should depend on
it.
At present, it should only be used for testing purposes on a machine you have 
physical access to (in case of unforeseen lockout of SSH) and should be used in conjunction with
public-key authentication or password-based authentication.

## I found a bug, usability concern, or typo...

Report it to the issues page. If it is security critical, report it without
giving details and we will find a way to get in contact.

## Didn't NIST deprecate 2FA through SMS?

[Yes](https://pages.nist.gov/800-63-3/sp800-63b.html).
Signal does not use SMS.
SMS was deprecated because it is not encrypted and therefore susceptible to a
huge number of attacks rendering it inappropriate for authentication.
Signal messages are end-to-end encrypted using strong modern cryptography.
Only someone with root access to the sending server or someone with
the ability to unlock your phone and Signal app can see the 2FA tokens.

## What is wrong with google-authenticator?

Google-authenticator is, as far as I can tell, a good product.
I would not go so far as to say that anything is "wrong" with it.
I do have some concerns though.

- Google-authenticator uses either HOTP (HMAC-based One-Time Password) or TOTP (Time-based
One-Time Password) algorithms in order to generate 2FA tokens.
With HOTP and TOTP, a pre-shared key and either a counter (HOTP) or an accurate
clock (TOTP) is used to generate the 2FA token.
The authenticating server never sends the user any token.
This makes HOTP vulnerable to denial-of-service attacks based on counter
desynchronization, and it makes TOTP vulnerable to replay attacks where an
attacker looking over your shoulder could use the same 2FA token as you to log
in to your account if she acts quickly enough.
So much for "one-time" passwords!

- Pre-shared keys are too easy to share or steal.
The pre-shared key for google-authenticator is shared either by scanning a 
QR code or by inputting the 26 alphanumeric character secret key.
It should not be easy to share a secret key like this.
Signal uses a key generated on your device automatically that is trusted by the
server on first use.
Should a new key be required, it is verified by fingerprint.
The user never has the chance to even see the secret key, and therefore is in
no danger of sharing it (even accidentally) or having it stolen by an
onlooker or camera.

- Google may store a copy of your secret key, and thus may have access to your
2FA tokens.
Upon creation of the secret key, the user is presented with a Google link
containing the QR code with their secret key.
Encoded in the URL is the secret key, whether it is for HOTP or TOTP, 
and the hostname of the machine for which the key is valid.
Google may store all of this information and also other fingerprinting
information about which device you visited the URL on.

## Can google see my authentication tokens with signal-authenticator?

Short answer: the tokens themselves NO, when the tokens are sent MAYBE.

Long answer: even if you register with a Google voice number, Google cannot see
your authentication tokens. The reason is that the tokens are end-to-end
encrypted and transmitted through Signal, not through SMS.
One end is your phone, the other end is your computer.
Neither end is your Google voice SMS inbox.
The only reason a Google voice number is suggested is because Signal
requires a "real" phone number in order to register, regardless of whether you are
registering from a phone or computer.
However, Signal itself depends on Google play services in a way that Google
may be able to tell when you receive an authentication token, but Google will 
not be able to distinguish between this authentication token
versus any other Signal message that you receive on your phone without doing
some kind of traffic correlation attack.
In any case, the tokens themselves are never seen by Google.
