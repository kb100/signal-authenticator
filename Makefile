CC = gcc
CFLAGS = -x c -D_POSIX_C_SOURCE -D_DEFAULT_SOURCE -std=c99
CWARN_FLAGS = -Wall -Wextra -Wno-long-long -Wno-variadic-macros
CSHAREDLIB_FLAGS = -fPIC -DPIC -shared -rdynamic
ifndef LIB_SECURITY_DIR
LIB_SECURITY_DIR = "/lib/x86_64-linux-gnu/security"
endif
ifndef SIGNAL_PROG
SIGNAL_PROG = "/usr/local/bin/signal-cli"
endif
ifndef SIGNAL_HOME
SIGNAL_HOME = "/var/lib/signal-cli"
endif
ifndef SIGNAL_USER
SIGNAL_USER = "signal-cli"
endif
PSA = pam_signal_authenticator

all: $(PSA).so

warn: CFLAGS += $(CWARN_FLAGS) 

$(PSA).so : $(PSA).c
	gcc $(CSHAREDLIB_FLAGS) $(CFLAGS) -DSIGNAL_PROG='$(SIGNAL_PROG)' -o $@ $<

install:
	install -m 644 $(PSA).so $(LIB_SECURITY_DIR)/$(PSA).so
	adduser --system --group --home $(SIGNAL_HOME) $(SIGNAL_USER)

uninstall:
	rm -f $(LIB_SECURITY_DIR)/$(PSA).so
	deluser --system $(SIGNAL_USER)

check-configs:
	@echo "Checking /etc/ssh/sshd_config"
	@grep -q "^AuthenticationMethods publickey,keyboard-interactive:pam" /etc/ssh/sshd_config \
		|| echo "AuthenticationMethods does not match"
	@grep -q "^RSAAuthentication yes" /etc/ssh/sshd_config \
		|| echo "RSAAuthentication does not match"
	@grep -q "^AuthorizedKeysFile" /etc/ssh/sshd_config \
		|| echo "AuthorizedKeysFile line not present"
	@grep -q "^PubkeyAuthentication yes" /etc/ssh/sshd_config \
		|| echo "PubkeyAuthentication does not match"
	@grep -q "^ChallengeResponseAuthentication yes" /etc/ssh/sshd_config \
		|| echo "ChallengeResponseAuthentication does not match"
	@grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config \
		|| echo "PasswordAuthentication does not match"
	@grep -q "^UsePAM yes" /etc/ssh/sshd_config \
		|| echo "UsePAM does not match"
	@echo "Checking /etc/pam.d/sshd_config"
	@grep -q -v "^[^#]\\+@include common-auth" /etc/pam.d/sshd \
		|| echo "@include common-auth not commented out"
	@grep -q "^auth[[:space:]]*required[[:space:]]pam_permit.so" /etc/pam.d/sshd \
		|| echo "pam_permit.so not found in config"
	@grep -q "^auth[[:space:]]*required[[:space:]]pam_signal_authenticator.so" /etc/pam.d/sshd \
		|| echo "pam_signal_authenticator.so not found in config"
	@echo "Checking ~/.signal_authenticator"
	@stat ~/.signal_authenticator 2>&1 >/dev/null || echo "~/.signal_authenticator not found"
	@stat ~/.signal_authenticator | grep -q -- "-[rwx-]\{6\}---" \
		|| echo "Need to chmod o-rwx ~/.signal_authenticator"
	@stat ~/.signal_authenticator | grep -q "Uid:[[:space:]]*([[:space:]]*$(shell id -u)/" \
		|| echo "Need to chown id -u -n):$(shell id -g -n) ~/.signal_authenticator"
	@stat ~/.signal_authenticator | grep -q "Gid:[[:space:]]*([[:space:]]*$(shell id -g)/" \
		|| echo "Need to chown $(shell id -u -n):$(shell id -g -n) ~/.signal_authenticator"
	@grep -q "^username=+[0-9]\\+" ~/.signal_authenticator \
		|| echo "username not found in ~/.signal_authenticator, watch out for stray spaces"
	@grep -q "^recipient=+[0-9]\\+" ~/.signal_authenticator \
		|| echo "recipient not found in ~/.signal_authenticator, watch out for stray spaces"
clean:
	rm -f pam_signal_authenticator.so

.PHONY: warn all clean install uninstall
