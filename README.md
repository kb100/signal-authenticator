# signal-authenticator

PAM module for two-factor authentication through [signal](https://github.com/WhisperSystems/Signal-Android).
Depends on [signal-cli](https://github.com/AsamK/signal-cli).
Install signal-cli and register with a google voice number before attempting
to use signal-authenticator.


This project is HIGHLY EXPERIMENTAL (pull requests welcome), has never been audited,
has been minimally tested, but does seem to work. DO NOT USE unless you understand
the risks. That said, it works ;)

At present, signal-authenticator does not implement standard flags/PAM conventions
like passing nullok
(will be implemented in the future).
It works on an opt in basis.
If `.signal_authenticator` is found in a user's home (even if invalid) it assumes the user has opted in.

In order to require public key authentication + allow users to opt in to two-factor authentication,
the important options for `/etc/ssh/sshd_config` are

```
AuthenticationMethods publickey,keyboard-interactive:pam
RSAAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile	%h/.ssh/authorized_keys
ChallengeResponseAuthentication yes
PasswordAuthentication no
UsePAM yes
```

and for `/etc/pam.d/sshd`

```
# comment out this common-auth line, this will ask for a passphrase even though
# we have disabled PasswordAuthentication
# @include common-auth
auth    required        pam_permit.so
auth    required        pam_signal_authenticator.so
```

To opt in, a user should create a file `.signal_authenticator` in their home directory
with contents

```
username=+15551234567
recipient=+15559999999
```

where `username` is the signal username (phone number) to send from, and
recipient is the signal username to send the token to.
Multiple recipients can be specified on their own lines.
Empty lines and lines that begin with `#` are ignored.
Do not include extra spaces anywhere on the line.

Get the build dependencies:

```
apt-get update
apt-get install build-essential libpam0g-dev
```

then

```
make
sudo make install LIB_SECURITY_DIR=/lib/x86_64-linux-gnu/security SIGNAL_PROG=/usr/local/bin/signal-cli
```

where you probably want to replace the lib security directory with the output
of `dirname $(locate pam_permit.so)`, and change the location of the signal-cli binary
appropriately.

Restart your sshd

```
sudo systemctl restart sshd
```

and test it

```
[user ~]$ ssh user@localhost
Enter passphrase for key '/home/user/.ssh/id_rsa': 
Authenticated with partial success.
(1-time code sent through signal!)
1-time code: mlfdolnvfb

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
No mail.
Last login: Wed Jun 29 16:36:29 2016 from 127.0.0.1
[user ~]$ 
```

## Hacking

The `log_message` function is ripped from the google-authenticator project.
It is very useful for testing, use like

```
log_message(LOG_INFO, "%s %d", "printf like formatting", 7);
```

and results appear in your syslog.
