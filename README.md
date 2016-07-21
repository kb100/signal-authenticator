# signal-authenticator

PAM module for two-factor authentication through [signal](https://github.com/WhisperSystems/Signal-Android).

This project is HIGHLY EXPERIMENTAL (pull requests welcome), has never been audited,
and has been minimally tested. 
DO NOT USE unless you understand the risks.
That said, it works ;)

## Requirements

- A phone with signal installed
- A different phone number (using a google voice number is fine)
- [signal-cli](https://github.com/AsamK/signal-cli)
- SSH server (assumed to be using pubkey authentication already)

## Options

`nullok` (recommended) allows users who have not opted in to bypass the
two-factor authentication, does not apply if user tried to opt in but has a
bad config

`nonull` requires all users to have properly setup two-factor authentication
(high chance of user locking themselves out of ssh)

`nostrictpermissions` (not recommended) allows users to make bad choices about 
the permissions of their config files while still allowing them to use
two-factor authentication

`systemuser` (default, recommended) indicates that the systemuser mode of operation should be selected
(all tokens sent from one phone number owned by system administrator)

`nosystemuser` indicates that the per-user mode of operation should be selected
(each user provides their own phone number to send tokens from)

## Setup

There are two supported modes that signal-authenticator can use:
systemwide sender, and per-user sender.
In the systemwide mode, all authentication tokens are sent through one signal number
owned by the system administrator.
In the per-user mode, each user provides their own signal number from which
authentication tokens are sent.
Follow the instructions below for your desired mode.

### Option 1: systemwide sender

Install [signal-cli](https://github.com/AsamK/signal-cli).

Next we get the build dependencies for signal-authenticator:

```
sudo apt-get update
sudo apt-get install build-essential libpam0g-dev
```

then

```
git clone "https://github.com/kb100/signal-authenticator.git"
cd signal-authenticator
make
sudo make install LIB_SECURITY_DIR=/lib/x86_64-linux-gnu/security SIGNAL_CLI=/usr/local/bin/signal-cli
```

where you probably want to replace the lib security directory with the output
of `dirname $(locate pam_permit.so)`, and change the location of the signal-cli binary
appropriately.

Next we need to register the signal-authenticator user's phone number with signal.

```
sudo su signal-authenticator
cd ~
signal-cli -u +15551234567 register
# registration CODE sent through signal
signal-cli -u +15551234567 verify CODE
```

Then create `.signal_authenticator` in their home directory
with contents

```
username=+15551234567
```

where the username is the signal username (phone number) to send from (which
was just registered).
Empty lines and lines that begin with `#` are ignored.
Do not include extra spaces anywhere on the line.

Make sure the signal-authenticator user is the only one who can read the
signal config and `.signal_authenticator` files.

```
chmod o-rwx ~/.signal_authenticator
chmod -R o-rwx ~/.config/signal
exit # we are done with the signal-authenticator user
```

Now we move to system configuration files.
In order to require public key authentication + allow users to opt in to two-factor authentication,
the important options for `/etc/ssh/sshd_config` are

```
# ... other options

# If you want to make sure it works before going live only listen to localhost
# ListenAddress 127.0.0.1
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
auth    required        pam_signal_authenticator.so nullok systemwide
```

Note: PAM config files are are more like scripts,
they are executed in order so make sure you put
those two lines exactly where the common-auth line used to be (near the top),
otherwise you may allow allow a user access before authenticating them (BAD!).

Restart your sshd

```
sudo systemctl restart sshd
```

Your signal-authenticator is now up and running! Though no one has opted in
yet, so if you test it you should see

```
[user ~]$ ssh user@localhost
Enter passphrase for key '/home/user/.ssh/id_rsa': 
Authenticated with partial success.
Authenticated fully. User has not enabled two-factor authentication.

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have new mail.
Last login: Wed Jul 20 19:59:45 2016 from 127.0.0.1
[user ~]$ 
```

To opt-in, a user should create a file `.signal_authenticator` in their home directory
with contents

```
recipient=+15559999999
```

where recipient is the signal username (phone number) to send authentication tokens to.
Multiple recipients can be specified on their own lines.
Empty lines and lines that begin with `#` are ignored.
Do not include extra spaces anywhere on the line.

Since phone numbers are not necessarily public information,
unless the `nostrictpermissions` option is passed to `pam_signal_authenticator.so`,
a user must own their `.signal_authenticator` file
and the file is not allowed to be read by other users.

```
chmod o-rwx ~/.signal_authenticator
```

Now the user's two-factor authentication is enabled, and it should look
something like:

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

### Option 2: per-user sender

Install [signal-cli](https://github.com/AsamK/signal-cli).

In order to require public key authentication + allow users to opt in to two-factor authentication,
the important options for `/etc/ssh/sshd_config` are

```
# ... other options

# If you want to make sure it works before going live only listen to localhost
# ListenAddress 127.0.0.1
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
auth    required        pam_signal_authenticator.so nullok nosystemwide
```

Note: PAM config files are are more like scripts,
they are executed in order so make sure you put
those two lines exactly where the common-auth line used to be (near the top),
otherwise you may allow allow a user access before authenticating them (BAD!).

Get the build dependencies:

```
sudo apt-get update
sudo apt-get install build-essential libpam0g-dev
```

then

```
git clone "https://github.com/kb100/signal-authenticator.git"
cd signal-authenticator
make
sudo make install LIB_SECURITY_DIR=/lib/x86_64-linux-gnu/security SIGNAL_CLI=/usr/local/bin/signal-cli
```

where you probably want to replace the lib security directory with the output
of `dirname $(locate pam_permit.so)`, and change the location of the signal-cli binary
appropriately.

Restart your sshd

```
sudo systemctl restart sshd
```

Your signal-authenticator is now up and running! Though no one has opted in
yet, so if you test it you should see

```
[user ~]$ ssh user@localhost
Enter passphrase for key '/home/user/.ssh/id_rsa': 
Authenticated with partial success.
Authenticated fully. User has not enabled two-factor authentication.

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have new mail.
Last login: Wed Jul 20 19:59:45 2016 from 127.0.0.1
[user ~]$ 
```

To opt in, a user should first register a phone number with signal-cli:

```
signal-cli -u +15551234567 register
# registration CODE sent through signal
signal-cli -u +15551234567 verify CODE
```

Then the user should create a file `.signal_authenticator` in their home directory
with contents

```
username=+15551234567
recipient=+15559999999
```

where the username is the signal username (phone number) to send from (which
was just registered), and recipient is the signal username to send the token to.
Multiple recipients can be specified on their own lines.
Empty lines and lines that begin with `#` are ignored.
Do not include extra spaces anywhere on the line.

Since phone numbers are not necessarily public information,
unless the `nostrictpermissions` option is passed to `pam_signal_authenticator.so`,
a user must own their `.signal_authenticator` file
and the file is not allowed to be read by other users.
Also make sure that the signal-cli config has similar permissions.

```
chmod o-rwx ~/.signal_authenticator
chmod -R o-rwx ~/.config/signal
```

Now the user's two-factor authentication is enabled, and it should look
something like:

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

## Hardening on multi-user systems

The default behavior of Linux is extremely permissive and allows any user to see
all processes run by another user.
In particular, other users on the system you are logging into can see
your authentication tokens.
Fortunately, the kernel has an option called `hidepid` to restrict user access
to the proc filesystem. The option `hidepid=0` is the default permissive behavior,
`hidepid=1` restricts users from reading other users proc files, and `hidepid=2`
additionally makes aforementioned proc files invisible to non root users.
For more information see `man proc`.

To enable the `hidepid` option on boot, add the following to `/etc/fstab`

```
proc    /proc   proc   defaults,hidepid=2 0   0
```

To temporarily test the `hidepid` option,

```
sudo mount -o remount,rw,hidepid=2 /proc
```

## Can google see my authentication tokens?

Short answer: the tokens themselves NO, when the tokens are sent MAYBE.

Long answer: even if you register with a google voice number, google cannot see
your authentication tokens. The reason is that the tokens are end-to-end
encrypted and transmitted through signal, not through sms.
One end is your phone, the other end is your computer.
Neither end is your google voice sms inbox.
The only reason a google voice number is suggested is because signal
requires a "real" phone number in order to register, regardless of whether you are
registering from a phone or computer.
However, signal itself depends on google play services in a way that google
may be able to tell when you receive an authentication token, but google will 
not be able to distinguish between this authentication token
versus any other signal message that you receive on your phone without doing
some kind of traffic correlation attack.
In any case, the tokens themselves are never seen by google.

## Something didn't work?

First run `make check-configs` and see if everything looks okay.
If something isn't working create an issue on the issues page and let me know
what's happening.
Errors are logged in your system logs using syslog.
If your sshd config has `SyslogFacility AUTH` (this is the default on
debian, e.g.) then the right log is probably `/var/log/auth`, 
but it may also be `/var/log/syslog` depending on your system.
You can also access logs using `sudo journalctl` if you are using systemd.

## Hacking

The `pam_syslog` function is useful for testing,

```
pam_syslog(pamh, LOG_INFO, "%s %d", "printf like formatting", 7);
```

and results appear in your syslog.
