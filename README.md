# signal-authenticator

PAM module for two-factor authentication through [signal](https://github.com/WhisperSystems/Signal-Android).
Depends on [signal-cli](https://github.com/AsamK/signal-cli).
Install signal-cli and register with a google voice number before attempting
to use signal-authenticator.

This project is HIGHLY EXPERIMENTAL (pull requests welcome), has never been audited,
has been minimally tested. DO NOT USE unless you understand the risks.
That said, it works ;)

At present, signal-authenticator accepts the `nullok` and `nonull` options
to indicate whether or not signal authentication is done on an opt in basis,
or whether it is required.
If `.signal_authenticator` is found in a user's home (even if invalid) 
it assumes the user has opted in.

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
auth    required        pam_permit.so nullok
auth    required        pam_signal_authenticator.so
```

Note: PAM config files are are more like scripts,
they are executed in order so make sure you put
those two lines exactly where the common-auth line used to be (near the top),
otherwise you may allow allow a user access before authenticating them (BAD!).

To opt in, a user should create a file `.signal_authenticator` in their home directory
with contents

```
username=+15551234567
recipient=+15559999999
```

where the username is the signal username (phone number) to send from, and
recipient is the signal username to send the token to.
Multiple recipients can be specified on their own lines.
Empty lines and lines that begin with `#` are ignored.
Do not include extra spaces anywhere on the line.

Since phone numbers are not necessarily public information, 
unless the `nostrictpermissions` option is passed to `pam_signal_authenticator.so`,
a user must own their `.signal_authenticator` file
and the file is not allowed to be read by other users:

```
chown user:user ~/.signal_authenticator
chmod o-rwx ~/.signal_authenticator
```

Get the build dependencies:

```
sudo apt-get update
sudo apt-get install build-essential libpam0g-dev
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
log_message(LOG_INFO, "%s %d", "printf like formatting", 7);
```

and results appear in your syslog.
