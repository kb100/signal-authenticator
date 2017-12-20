# signal-authenticator

PAM module for two-factor authentication through [Signal](https://github.com/WhisperSystems/Signal-Android).

This project is in its ALPHA stage.
It has been tested only by me for one year.
It has not been professionally audited and you should not depend on it for your security at this time.
The project is, however, ready for enthusiastic testers and contributors.

Report bugs to the issues page and please rebase to my
master branch before submitting any pull requests.
See the [contributing page](CONTRIBUTING.md) for details.

Releases are now signed with my GPG key with fingerprint

```
6E59 B8E5 A268 E206 A086  329E 507E 1F83 7C14 FFA9
```

- [Requirements](#requirements)
- [Options](#options)
- [Setup (basic)](#setup-basic)
- [Setup (share Signal number across multiple systems)](#setup-share-signal-number-across-multiple-systems)
- [Setup (use the system dbus)](#setup-use-the-system-dbus)
- [How can I require other combinations of authentication?](#how-can-i-require-other-combinations-of-authentication)
- [Managing signal-authenticator manually](#managing-signal-authenticator-manually)
- [Something didn't work?](#something-didnt-work)
- [Uninstalling](#uninstalling)
- [FAQ](FAQ.md)
- [Contributing](CONTRIBUTING.md)

## Requirements

- A phone with Signal installed (for receiving 1-time tokens)
- A different phone number (using a google voice number is fine)
- [signal-cli](https://github.com/AsamK/signal-cli) (version >= 0.5.3)
- SSH server (assumed to be using publickey authentication already)

## Options

`-n`, `--nullok` (recommended) allows users who have not opted in to bypass Signal
authentication, does not apply if user tried to opt in but has a bad config

`-N`, `--nonull` requires all users to have properly setup Signal authentication
(high chance of user locking themselves out of ssh)

`-p`, `--nostrictpermissions` (not recommended) allows users to make bad choices about 
the permissions of their config files while still allowing them to use
two-factor authentication

`-s`, `--silent` no warnings or errors will be written to the system log

`-d`, `--debug` print warnings and errors to the system log even if the `PAM_SILENT` flag is passed to PAM

`-I`, `--ignore-spaces` ignore spaces in user's response (allowed characters must not contain
a space)

`-a`, `--add-space-every [n]` add a space every n characters so users can more easily
read the token (implies `--ignore-spaces`)

`-D`, `--dbus` speed things up by using signal-cli's experimental system dbus interface (requires
signal-authenticator.service to be enabled)

`-t`, `--time-limit [n]` tokens expire after n seconds. By default there is no
time limit.

`-C`, `--allowed-chars [chars]` tokens will be made up of these characters only. The
number of allowed characters must be a divisor of 256. The default allowed
characters are `abcdefghjkmnpqrstuvwxyz123456789`.

`-T`, `--token-len [n]` sets the length of 1-time tokens. The default token
length is 12.

## Setup (basic)

Install [signal-cli](https://github.com/AsamK/signal-cli) and java:

```
sudo apt-get update && sudo apt-get upgrade
sudo apt-get install default-jre
export VERSION=0.5.6
wget https://github.com/AsamK/signal-cli/releases/download/v"${VERSION}"/signal-cli-"${VERSION}".tar.gz
sudo tar xf signal-cli-"${VERSION}".tar.gz -C /opt
sudo ln -sf /opt/signal-cli-"${VERSION}"/bin/signal-cli /usr/local/bin/
```

Get the build dependencies, download, make, and install signal-authenticator:

```
sudo apt-get install build-essential libpam0g-dev
git clone "https://github.com/kb100/signal-authenticator.git"
# or fork your own copy and clone that
cd signal-authenticator
make
sudo make install
```

Next setup the signal-authenticator user's Signal number:

```
sudo signal-auth-setup
```

This will prompt you for the Signal number (including plus sign and country code) 
the authenticator will use to SEND tokens, e.g. `+15551231234`.
It is recommended and easy to create a google voice number for this step.
This step (re)registers the given number with Signal servers, so
DO NOT use the number that you want to RECEIVE tokens at for this step.

We give instructions assuming that public key authentication is already setup and that
the desired authentication is public key AND Signal authentication.
For other authentication combinations, see
[How can I require other combinations of authentication?](#how-can-i-require-other-combinations-of-authentication).
In order to require public key authentication and allow users to opt in to two-factor authentication,
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
@include signal-authenticator
```

Note: PAM config files are are more like scripts,
they are executed in order so make sure you put
the new include signal-authenticator line exactly where the common-auth line used to be (near the top),
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
There is no danger of messing up your already installed Signal at this step.
This will create the necessary
`.signal_authenticator` file in the user's home directory.

Now the user's two-factor authentication is enabled, and it should look
something like:

```
[user ~]$ ssh user@localhost
Enter passphrase for key '/home/user/.ssh/id_rsa': 
Authenticated with partial success.
(1-time code sent through Signal!)
1-time code: mlfdolnvfb
Last login: Wed Jun 29 16:36:29 2016 from 127.0.0.1
[user ~]$ 
```

## Setup (share Signal number across multiple systems)

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

## Setup (use the system dbus)

Using a long-lived signal-cli instance that uses the system dbus offers a noticeable
speedup for users because it bypasses signal-cli's significant startup overhead.
First, setup signal-authenticator without the dbus option.
The dbus service file, dbus configuration file, and the systemd service file
should already be available in `/usr/local/share/signal-authenticator`.
Theoretically, systemd is not required and you could use another system daemon
manager, but our instructions assume you are using systemd.
Copy the files to the correct locations, have sed put in the correct phone number to
send tokens from, and enable the service:

```
DIR="/usr/local/share/signal-authenticator"
sudo cp $DIR/org.asamk.Signal.conf /etc/dbus-1/system.d
sudo cp $DIR/org.asamk.Signal.service /usr/share/dbus-1/system-services
sudo cp $DIR/signal-authenticator.service /etc/systemd/system
username=$(sudo cat ~signal-authenticator/.signal_authenticator | grep -o "+.*$")
sudo sed -i -e "s|%number%|$username|" /etc/systemd/system/signal-authenticator.service
sudo systemctl daemon-reload
sudo systemctl enable signal-authenticator.service
sudo systemctl reload dbus.service
```
At this point, the `--dbus` flag will work when passed to signal-authenticator
in your `/etc/pam.d/sshd`.
While the long-lived signal-cli is running, the authenticator will ONLY work
with the `--dbus` flag.
If you want to go back to not using the dbus, you must stop the
signal-authenticator service:

```
systemctl stop signal-authenticator.service
systemctl disable signal-authenticator.service
```

## How can I require other combinations of authentication?

Other multi-factor authentication combinations can be achieved by changing
`/etc/pam.d/sshd` and `/etc/ssh/sshd_config`.
In the below examples, only the parts of the files that need to be changed
from what was described above are shown.

#### Public key AND Signal

`/etc/pam.d/sshd`
```
# comment out this common-auth line
# @include common-auth
@include signal-authenticator
```

`/etc/ssh/sshd_config`
```
AuthenticationMethods publickey,keyboard-interactive:pam
```

#### Public key AND Password AND Signal

`/etc/pam.d/sshd`
```
@include common-auth
@include signal-authenticator
```

`/etc/ssh/sshd_config`
```
AuthenticationMethods publickey,keyboard-interactive:pam
```

#### Public key OR (Password AND Signal)

`/etc/pam.d/sshd`
```
@include common-auth
@include signal-authenticator
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
@include signal-authenticator
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

## Managing signal-authenticator manually

signal-authenticator works simply by using signal-cli and keeping the config in
the signal-authenticator user's home directory `/var/lib/signal-authenticator`.
If you need to do things like trust a user's new key, remove a user from the
trust store, or reset a session from the server side, you may get fine control
by switching to the signal-authenticator user with `sudo su
signal-authenticator` and using signal-cli manually.
If you want to completely start over with a fresh config, new keys, and
reregister Signal, you can use `sudo signal-auth-setup override`
instead.

## Something didn't work?

If something isn't working create an issue on the issues page and let me know
what's happening.
Errors are logged in your system logs using syslog.
If your sshd config has `SyslogFacility AUTH` (this is the default on
debian, e.g.) then the right log is probably `/var/log/auth`, 
but it may also be `/var/log/syslog` depending on your system.
You can also access logs using `sudo journalctl` if you are using systemd.

## Uninstalling

If you want to uninstall signal-authenticator, first remove it from your pam
configuration file `/etc/pam.d/sshd` and sshd
configuration file `/etc/ssh/sshd_config`.

To remove signal-authenticator but leave configuration files (e.g. if you plan
on reinstalling shortly), from the repository directory run

```
sudo make uninstall
```

To remove signal-authenticator, including configuration files (pam
configuration, signal-authenticator home directory, etc.) run

```
sudo make purge
```

Note, this operation deletes your signal-authenticator's private keys.
If you reinstall, you will have to register with Signal servers again and 
new private keys will be generated. Any previous users will receive key change 
notices the next time they receive a one-time token from your authenticator.
