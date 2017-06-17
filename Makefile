CC = gcc
CFLAGS = -x c -D_POSIX_C_SOURCE -D_DEFAULT_SOURCE -std=c99
CWARN_FLAGS = -Wall -Wextra -Wno-long-long -Wno-variadic-macros
CSHAREDLIB_FLAGS = -fPIC -DPIC -shared -rdynamic
ifndef LIB_SECURITY_DIR
LIB_SECURITY_DIR = "/lib/x86_64-linux-gnu/security"
endif
ifndef SIGNAL_CLI
SIGNAL_CLI = "/usr/local/bin/signal-cli"
endif
ifndef SIGNAL_SHELL
SIGNAL_SHELL = "/bin/sh"
endif
ifndef SIGNAL_HOME
SIGNAL_HOME = "/var/lib/signal-authenticator"
endif
ifndef PREFIX
PREFIX = "/usr/local"
endif
ifndef SHARE_DIR
SHARE_DIR = $(PREFIX)/share
endif
SIGNAL_USER = "signal-authenticator"
PSA = pam_signal_authenticator
SA = signal-authenticator

all: $(PSA).so

warn: CFLAGS += $(CWARN_FLAGS) 
warn: $(PSA).so

$(PSA).so : $(PSA).c
	gcc $(CSHAREDLIB_FLAGS) $(CFLAGS) -DSIGNAL_CLI='$(SIGNAL_CLI)' -o $@ $<

install:
	install -m 644 $(PSA).so $(LIB_SECURITY_DIR)/$(PSA).so
	install -m 755 signal-auth-setup $(PREFIX)/bin/signal-auth-setup 
	install -m 755 signal-auth-link $(PREFIX)/bin/signal-auth-link 
	install -m 755 signal-auth-opt-in $(PREFIX)/bin/signal-auth-opt-in 
	mkdir -p $(SHARE_DIR)/$(SA)
	install -m 644 share/org.asamk.Signal.conf $(SHARE_DIR)/$(SA)/org.asamk.Signal.conf
	install -m 644 share/org.asamk.Signal.service $(SHARE_DIR)/$(SA)/org.asamk.Signal.service
	install -m 644 share/signal-authenticator.service $(SHARE_DIR)/$(SA)/signal-authenticator.service
	install -m 644 share/sample_pam_sshd $(SHARE_DIR)/$(SA)/sample_pam_sshd
	install -m 644 share/sample_sshd_config $(SHARE_DIR)/$(SA)/sample_sshd_config
	adduser --system --quiet --group --shell $(SIGNAL_SHELL) --home $(SIGNAL_HOME) $(SIGNAL_USER)

uninstall:
	rm -f $(LIB_SECURITY_DIR)/$(PSA).so
	rm -f $(PREFIX)/bin/signal-auth-setup
	rm -f $(PREFIX)/bin/signal-auth-link
	rm -f $(PREFIX)/bin/signal-auth-opt-in
	rm -rf $(SHARE_DIR)/$(SA)
	deluser --system --quiet $(SIGNAL_USER)

clean:
	rm -f $(PSA).so

.PHONY: warn all clean install uninstall
