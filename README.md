# signal-authenticator

PAM module for two-factor authentication through [signal](https://github.com/WhisperSystems/Signal-Android).

This project is in its ALPHA stage.
It is HIGHLY EXPERIMENTAL,
has never been audited,
and has been minimally tested. 
DO NOT USE unless you understand the risks.

Contributors welcome! Report bugs to the issues page and please rebase to my
master branch before submitting any pull requests.
See the [contributing page](CONTRIBUTING.md) for details.

## Requirements

- A phone with signal installed (for receiving 1-time tokens)
- A different phone number (using a google voice number is fine)
- [signal-cli](https://github.com/AsamK/signal-cli) (version >= 0.5.3)
- SSH server (assumed to be using publickey authentication already)

## Options

`nullok` (recommended) allows users who have not opted in to bypass signal
authentication, does not apply if user tried to opt in but has a bad config

`nonull` requires all users to have properly setup signal authentication
(high chance of user locking themselves out of ssh)

`nostrictpermissions` (not recommended) allows users to make bad choices about 
the permissions of their config files while still allowing them to use
two-factor authentication

`silent` no warnings or errors will be written to the system log

`debug` print warnings and errors to the system log even if the `PAM_SILENT` flag is passed to PAM

## Setup

Install [signal-cli](https://github.com/AsamK/signal-cli) and java:

```
sudo apt-get update
sudo apt-get install default-jre
export VERSION=0.5.3
wget https://github.com/AsamK/signal-cli/releases/download/v"${VERSION}"/signal-cli-"${VERSION}".tar.gz
sudo tar xf signal-cli-"${VERSION}".tar.gz -C /opt
sudo ln -sf /opt/signal-cli-"${VERSION}"/bin/signal-cli /usr/local/bin/
```

Get the build dependencies, download, make, and install signal-authenticator:

```
sudo apt-get update
sudo apt-get install build-essential libpam0g-dev
git clone "https://github.com/kb100/signal-authenticator.git"
# or fork your own copy and clone that
cd signal-authenticator
make
sudo make install
```

Next setup the signal-authenticator user's signal number:

```
sudo signal-auth-setup
```

This will prompt you for the signal number (including plus sign and country code) 
the authenticator will use to SEND tokens, e.g. `+15551231234`.
It is recommended and easy to create a google voice number for this step.
DO NOT use the number that you want to RECEIVE tokens at for this step.

In order to require public key authentication + allow users to opt in to two-factor authentication,
the important options for `/etc/ssh/sshd_config` are

```
# ... other options

# If you want to make sure it works before going live only listen to localhost
# ListenAddress 127.0.0.1
AuthenticationMethods publickey,keyboard-interactive:pam
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
auth    required        pam_signal_authenticator.so nullok
```

Note: PAM config files are are more like scripts,
they are executed in order so make sure you put
those two lines exactly where the common-auth line used to be (near the top),
otherwise you may allow a user access before authenticating them (BAD!).

Restart your sshd:

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
Last login: Wed Jul 20 19:59:45 2016 from 127.0.0.1
[user ~]$ 
```

To opt in, a user should run
```
signal-auth-opt-in
```
which will ask the user for the phone number to RECEIVE tokens at.
This will create the necessary
`.signal_authenticator` file in the user's home directory.

Now the user's two-factor authentication is enabled, and it should look
something like:

```
[user ~]$ ssh user@localhost
Enter passphrase for key '/home/user/.ssh/id_rsa': 
Authenticated with partial success.
(1-time code sent through signal!)
1-time code: mlfdolnvfb
Last login: Wed Jun 29 16:36:29 2016 from 127.0.0.1
[user ~]$ 
```

## Setup (share signal number across multiple systems)

If you administrate multiple servers and would like to have
signal-authenticator share a single real phone number for all of your servers, 
this section is for you.

Pick one of your machines as primary and follow the setup for the previous
section on that machine.

On all other machines follow the
instructions of the previous section, except:
use

```
sudo signal-auth-setup as-linked
```

which will provide a tsdevice:/... link.
The program will hang until you complete the rest of the process.
Copy this link and via a secure channel transmit it to the primary machine.
On the primary machine run

```
sudo signal-auth-link add
```

which will prompt you to paste the tsdevice:/... link.
The two devices will then link and the signal number is shared between the
linked devices. The primary is the only one that can add or remove linked
devices.

## How can I require other combinations of authentication?

Other multi-factor authentication combinations can be achieved by changing
`/etc/pam.d/sshd` and `/etc/ssh/sshd_config`.
In the below examples, only the parts of the files that need to be changed
from what was described above are shown.

#### Public key AND Signal

`/etc/pam.d/sshd`
```
#@include common-auth
auth	required	pam_permit.so
auth	required	pam_signal_authenticator.so nullok 
```

`/etc/ssh/sshd_config`
```
AuthenticationMethods publickey,keyboard-interactive:pam
```

#### Public key AND Password AND Signal

`/etc/pam.d/sshd`
```
@include common-auth
#auth	required	pam_permit.so
auth	required	pam_signal_authenticator.so nullok 
```

`/etc/ssh/sshd_config`
```
AuthenticationMethods publickey,keyboard-interactive:pam
```

#### Public key OR (Password AND Signal)

`/etc/pam.d/sshd`
```
@include common-auth
#auth	required	pam_permit.so
auth	required	pam_signal_authenticator.so nullok 
```

`/etc/ssh/sshd_config`
```
AuthenticationMethods publickey keyboard-interactive:pam
```

#### Password AND Signal

**(Highly discouraged, you should allow public key access)**

`/etc/pam.d/sshd`
```
@include common-auth
#auth	required	pam_permit.so
auth	required	pam_signal_authenticator.so nullok 
```

`/etc/ssh/sshd_config`
```
AuthenticationMethods keyboard-interactive:pam
```

#### (Public key AND Signal) OR (Password AND Signal)

Unfortunately, due to the way that ssh interacts with PAM, this is not
possible. The following **does not work** and will break your logins

`/etc/ssh/sshd_config`
```
# DON'T DO THIS
AuthenticationMethods publickey,keyboard-interactive:pam password,keyboard-interactive:pam
```

Although one would hope that this would work, when PAM is enabled "password"
ALWAYS uses PAM, which we do not want since we are using PAM for Signal
authentication. If you know a way around this please let me know.

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

## Managing signal-authenticator manually

signal-authenticator works simply by using signal-cli and keeping the config in
the signal-authenticator user's home directory `/var/lib/signal-authenticator`.
If you need to do things like trust a user's new key, remove a user from the
trust store, or reset a session from the server side, you may get fine control
by switching to the signal-authenticator user with `sudo su
signal-authenticator` and using signal-cli manually.
If you want to completely start over with a fresh config, new keys, and
reregister signal, you can use `sudo signal-auth-setup override`
instead.

## Something didn't work?

If something isn't working create an issue on the issues page and let me know
what's happening.
Errors are logged in your system logs using syslog.
If your sshd config has `SyslogFacility AUTH` (this is the default on
debian, e.g.) then the right log is probably `/var/log/auth`, 
but it may also be `/var/log/syslog` depending on your system.
You can also access logs using `sudo journalctl` if you are using systemd.
