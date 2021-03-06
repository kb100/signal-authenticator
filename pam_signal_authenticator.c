/*
 * pam_signal_authenticator.c
 * Copyright (C) 2016 James Murphy
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <time.h>

#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define VERSION "0.4"
#define MODULE_NAME "pam_signal_authenticator.so"
#ifndef SIGNAL_CLI
#define SIGNAL_CLI "/usr/local/bin/signal-cli"
#endif
#define SIGNAL_CLI_LEN ((sizeof(SIGNAL_CLI)/sizeof(SIGNAL_CLI[0]))-1)

#ifndef MAX_BUF_SIZE
#define MAX_BUF_SIZE 1024
#endif
#ifndef TOKEN_LEN
#define TOKEN_LEN 12
#endif
#ifndef MAX_TOKEN_LEN
#define MAX_TOKEN_LEN 256
#endif
#ifndef MINIMUM_BITS_OF_ENTROPY
#define MINIMUM_BITS_OF_ENTROPY 40
#endif
#ifndef TOKEN_TIME_TO_EXPIRE
#define TOKEN_TIME_TO_EXPIRE 90
#endif

#ifndef CONFIG_FILE
#define CONFIG_FILE ".signal_authenticator"
#endif
#ifndef SYSTEM_SIGNAL_USER
#define SYSTEM_SIGNAL_USER "signal-authenticator"
#endif

#ifndef ALLOWED_CHARS_DEFAULT
#define ALLOWED_CHARS_DEFAULT "abcdefghjkmnpqrstuvwxyz123456789"
#endif
#define ALLOWED_CHARS_LEN_DEFAULT ((sizeof(ALLOWED_CHARS_DEFAULT)/sizeof(ALLOWED_CHARS_DEFAULT[0]))-1)

#ifndef SSH_PROMPT
#define SSH_PROMPT "Input 1-time code: "
#endif
#ifndef SIGNAL_MESSAGE_PREFIX
#define SIGNAL_MESSAGE_PREFIX "1-time code: "
#endif
#ifndef SIGNAL_MESSAGE_SUFFIX
#define SIGNAL_MESSAGE_SUFFIX ""
#endif
#ifndef MAX_RECIPIENTS
#define MAX_RECIPIENTS 5
#endif
#ifndef MAX_USERNAME_LEN
#define MAX_USERNAME_LEN 32
#endif

typedef struct params {
	bool nullok;
	bool strict_permissions;
	bool silent;
	bool ignore_spaces;
	bool use_dbus;
	time_t time_limit;
	char *allowed_chars;
	size_t allowed_chars_len;
	size_t token_len;
	size_t add_space_every;
} Params;

void errorx(pam_handle_t *pamh, const Params *params, const char *msg, ...)
{
	va_list ap;
	va_start(ap, msg);
	if (!params || !params->silent)
		pam_vsyslog(pamh, LOG_ERR, msg, ap);
	va_end(ap);
}

void free_str_array(char *ptr[], size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (ptr[i])
			free(ptr[i]);
	}
}

int get_2fa_config_filename(const char* home_dir, char fn_buf[MAX_BUF_SIZE])
{
	if (home_dir == NULL || fn_buf == NULL)
		return PAM_AUTH_ERR;
	size_t buf_size = sizeof(char[MAX_BUF_SIZE]);
	int snp_ret = snprintf(fn_buf, buf_size,
			"%s/"CONFIG_FILE, home_dir);
	if (snp_ret < 0 || (size_t)snp_ret >= buf_size)
		return PAM_AUTH_ERR;
	return PAM_SUCCESS;
}

void make_spaced_version_of_token(const Params *params, const char * token,
			 char spaced_token_buf[MAX_BUF_SIZE])
{
	if (!params || !params->add_space_every || !token || !spaced_token_buf)
		return;
	size_t spaces_to_add = 2 * (params->token_len / params->add_space_every);
	if (spaces_to_add + params->token_len + 1 >= MAX_BUF_SIZE)
		return;
	for (size_t i = 1; *token; i++, token++, spaced_token_buf++) {
		*spaced_token_buf = *token;
		if (*(token+1) && i % params->add_space_every == 0) {
			*++spaced_token_buf = ' ';
			*++spaced_token_buf = ' ';
		}
	}
	*spaced_token_buf = '\0';
}

int make_message(const Params *params, const char *token, char message_buf[MAX_BUF_SIZE])
{
	if (token == NULL || message_buf == NULL)
		return PAM_AUTH_ERR;

	char spaced_token_buf[MAX_BUF_SIZE] = {0};
	if (params->add_space_every) {
		make_spaced_version_of_token(params, token, spaced_token_buf);
		token = spaced_token_buf;
	}

	size_t buf_size = sizeof(char[MAX_BUF_SIZE]);
	int snp_ret = snprintf(message_buf, buf_size,
			"%s%s%s", SIGNAL_MESSAGE_PREFIX, token, SIGNAL_MESSAGE_SUFFIX);
	if (snp_ret < 0 || (size_t)snp_ret >= buf_size)
		return PAM_AUTH_ERR;
	return PAM_SUCCESS;
}

bool configs_exist_permissions_good(
		pam_handle_t *pamh,
		const Params *params,
		struct passwd *pw,
		struct passwd *signal_pw,
		const char *config_filename,
		const char *signal_config_filename)
{
	struct stat s = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, {0, 0}, {0, 0}, {0, 0}, {0}};
	int result = stat(config_filename, &s);
	if (result < 0) /* File does not exist or something else fails */
		return false;
	if (params->strict_permissions) {
		if (s.st_uid != pw->pw_uid) {
			errorx(pamh, params, "User uid=%d, but config uid=%d", pw->pw_uid, s.st_uid);
			return false;
		} else if (s.st_gid != pw->pw_gid) {
			errorx(pamh, params, "User gid=%d, but config gid=%d", pw->pw_gid, s.st_gid);
			return false;
		} else if ((s.st_mode & S_IROTH) || (s.st_mode & S_IWOTH) || (s.st_mode & S_IXOTH)) {
			errorx(pamh, params, "config has bad permissions, try chmod o-rwx");
			return false;
		}
	}

	result = stat(signal_config_filename, &s);
	if (result < 0)
		return false;
	/* Option --nostrictpermissions does not apply to the admin */
	if (s.st_uid != signal_pw->pw_uid || s.st_gid != signal_pw->pw_gid) {
		errorx(pamh, params, "signal-authenticator uid=%d, but config uid=%d",
			signal_pw->pw_uid, s.st_uid);
		return false;
	}
	if ((s.st_mode & S_IROTH) || (s.st_mode & S_IWOTH) || (s.st_mode & S_IXOTH)) {
		errorx(pamh, params, "signal-authenticator config has bad permissions, try chmod o-rwx");
		return false;
	}
	return true;
}

int drop_privileges(struct passwd *pw)
{
	int gid_ret = setgid(pw->pw_gid);
	int uid_ret = setuid(pw->pw_uid);
	if (uid_ret != 0 || gid_ret != 0)
		return PAM_AUTH_ERR;
	return PAM_SUCCESS;
}


/*
 * Gives the number of bits of entropy of a token of length token_len with
 * allowed_chars_len possible characters.
 */
int bits_of_entropy(size_t token_len, size_t allowed_chars_len)
{
	/* allowed_chars_len is a divisor of 256, and thus a power of 2 */
	size_t power = 0;
	while (allowed_chars_len > 1) {
		allowed_chars_len >>= 1;
		power++;
	}
	return power * token_len;
}

/*
 * Will be token_len many characters from allowed_chars.
 * Result is uniform string in allowed_chars because allow_chars_len is a
 * divisor of 256.
 */
int generate_random_token(char token_buf[MAX_TOKEN_LEN + 1], const Params *params)
{
	FILE *urandom = fopen("/dev/urandom", "r");
	const char *allowed_chars = params->allowed_chars;
	size_t n = params->allowed_chars_len;
	size_t token_len = params->token_len;

	if (urandom == NULL)
		return PAM_AUTH_ERR;
	unsigned char c;
	for (size_t i = 0; i < token_len; i++) {
		c = fgetc(urandom);
		token_buf[i] = allowed_chars[c % n];
	}
	token_buf[token_len] = '\0';
	if (fclose(urandom) != 0)
		return PAM_AUTH_ERR;
	return PAM_SUCCESS;
}

bool looks_like_phone_number(const char *str)
{
	if (str == NULL)
		return false;
	size_t len = strlen(str);
	if (len == 0 || len > MAX_USERNAME_LEN)
		return false;
	while (*str) {
		if (!(*str == '+' || ('0' <= *str && *str <= '9')))
			return false;
		str++;
	}
	return true;
}

int parse_signal_username(const char *config_filename, char username_buf[MAX_USERNAME_LEN + 1])
{
	FILE *config_fp = fopen(config_filename, "r");
	if (config_fp == NULL)
		return PAM_AUTH_ERR;

	bool username_found = false;
	char line_buf[MAX_BUF_SIZE] = {0};
	while (!username_found && fgets(line_buf, sizeof(line_buf), config_fp) != NULL) {
		size_t len = strlen(line_buf);
		if (line_buf[len - 1] != '\n')
		   return PAM_AUTH_ERR;
		line_buf[len - 1] = '\0';
		const char *line = line_buf;
		switch (*line) {
		case '#': /* Comment? */
		case '\0': /* Empty line? */
			break;
		case 'u': /* username */
			if (strncmp(line, "username=", strlen("username=")) != 0)
				goto cleanup_then_return_auth_err;
			line += strlen("username=");
			if (looks_like_phone_number(line)) {
				/* It is known here that strlen(line) <= MAX_USERNAME_LEN */
				strncpy(username_buf, line, MAX_USERNAME_LEN + 1);
				username_found = true;
			} else {
				goto cleanup_then_return_auth_err;
			}
			break;
		default: /* Ignore garbage */
			break;
		}
	}
	if (fclose(config_fp) != 0 || !username_found)
		return PAM_AUTH_ERR;

	return PAM_SUCCESS;

cleanup_then_return_auth_err:
	fclose(config_fp);
	return PAM_AUTH_ERR;
}

int parse_signal_recipients(const char *config_filename, char *recipients_arr[MAX_RECIPIENTS])
{
	FILE *config_fp = fopen(config_filename, "r");
	if (config_fp == NULL)
		return PAM_AUTH_ERR;

	int recipient_count = 0;
	char line_buf[MAX_BUF_SIZE] = {0};
	while (fgets(line_buf, sizeof(line_buf), config_fp) != NULL) {
		size_t len = strlen(line_buf);
		if (line_buf[len - 1] != '\n')
		   return PAM_AUTH_ERR;
		line_buf[len - 1] = '\0';
		const char *line = line_buf;
		switch (*line) {
		case '#': /* Comment? */
		case '\0': /* Empty line? */
			break;
		case 'r': /* recipient */
			if (strncmp(line, "recipient=", strlen("recipient=")) != 0)
				goto cleanup_then_return_auth_err;
			line += strlen("recipient=");
			if (looks_like_phone_number(line)) {
				size_t username_len = strlen(line);
				recipients_arr[recipient_count] = calloc(username_len + 1, sizeof(char));
				if (!recipients_arr[recipient_count])
					goto cleanup_then_return_auth_err;
				strcpy(recipients_arr[recipient_count++], line);
			} else {
				goto cleanup_then_return_auth_err;
			}
			break;
		default:
			break;
		}

		/*
		 * If the user specified more than MAX_RECIPIENTS recipients, just use
		 * the first few
		 */
		if (recipient_count == MAX_RECIPIENTS)
			break;
	}
	if (fclose(config_fp) != 0 || recipient_count == 0)
		return PAM_AUTH_ERR;

	return PAM_SUCCESS;

cleanup_then_return_auth_err:
	fclose(config_fp);
	return PAM_AUTH_ERR;
}

int build_signal_send_command(
		const Params *params,
		const char *sender,
		char *recipients[MAX_RECIPIENTS],
		const char *args[4 + MAX_RECIPIENTS + 1])
{
	if (sender == NULL || recipients == NULL || args == NULL)
		return PAM_AUTH_ERR;
	int dbus_offset = params->use_dbus ? -1 : 0;
	args[0] = "signal-cli";
	if (!params->use_dbus) {
		args[1] = "-u";
		args[2] = sender;
	} else {
		args[1] = "--dbus-system";
	}
	args[3 + dbus_offset] = "send";
	for (size_t i = 0; i <  MAX_RECIPIENTS; i++) {
		if (recipients[i] && recipients[i][0]) {
			args[i + 4 + dbus_offset] = recipients[i];
		} else {
			args[i + 4 + dbus_offset] = (const char *)NULL;
			break;
		}
	}
	args[4 + dbus_offset + MAX_RECIPIENTS] = (const char *)NULL;
	return PAM_SUCCESS;
}

int build_signal_receive_command(const char *username, const char *args[8])
{
	if (username == NULL || args == NULL)
		return PAM_AUTH_ERR;
	args[0] = "signal-cli";
	args[1] = "-u";
	args[2] = username;
	args[3] = "receive";
	args[4] = "-t";
	args[5] = "0";
	args[6] = "--ignore-attachments";
	args[7] = (const char *)NULL;
	return PAM_SUCCESS;
}

int signal_cli(pam_handle_t *pamh, const Params *params,
		struct passwd *drop_pw, char *const argv[],
		const char *msg)
{
	pid_t c_pid;
	int status;
	int fd[2];

	if (msg && pipe(fd) != 0) {
		errorx(pamh, params, "failed to make pipe for sending message");
		return PAM_AUTH_ERR;
	}

	c_pid = fork();
	if (c_pid == 0) {
		/* child */
		int fdnull = open("/dev/null", O_RDWR);
		if (!fdnull)
			exit(EXIT_FAILURE);
		else if (msg && close(fd[1]) != 0)
			exit(EXIT_FAILURE);
		else if (dup2(msg ? fd[0] : fdnull, STDIN_FILENO) < 0)
			exit(EXIT_FAILURE);
		else if (msg && close(fd[0]) != 0)
			exit(EXIT_FAILURE);
		else if (dup2(fdnull, STDOUT_FILENO) < 0)
			exit(EXIT_FAILURE);
		else if (dup2(fdnull, STDERR_FILENO) < 0)
			exit(EXIT_FAILURE);
		else if (close(fdnull) != 0)
			exit(EXIT_FAILURE);
		else if (drop_privileges(drop_pw) != PAM_SUCCESS)
			exit(EXIT_FAILURE);
		execv(SIGNAL_CLI, argv);
	} else if (c_pid <  0) {
		errorx(pamh, params, "failed to fork child for sending message");
		return PAM_AUTH_ERR;
	}
	/* parent */
	bool failure = false;
	if (msg) {
		failure |= close(fd[0]);
		size_t n = strlen(msg);
		failure |= write(fd[1], msg, n) != (ssize_t)n;
		failure |= close(fd[1]);
	}
	wait(&status);

	if (failure || !WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
		return PAM_AUTH_ERR;

	return PAM_SUCCESS;
}

/* result is a valid string as long as input is */
void delete_spaces_inplace(char str[MAX_BUF_SIZE])
{
	if(!str)
		return;
	size_t i = 0;
	size_t j = 0;
	while (j < MAX_BUF_SIZE) {
		if (str[j] == ' ')
			j++;
		else
			str[i++] = str[j++];
	}
	while (i < MAX_BUF_SIZE) {
		str[i++] = '\0';
	}
}

int wait_for_response(pam_handle_t *pamh, const Params *params, char response_buf[MAX_BUF_SIZE])
{
	struct timespec sent_time;
	struct timespec completed_time;
	if (params->time_limit) {
		clock_gettime(CLOCK_MONOTONIC, &sent_time);
		pam_info(pamh, "Token expires in %zu seconds.", params->time_limit);
	}

	char *response = NULL;
	int ret = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &response, SSH_PROMPT);
	if (ret != PAM_SUCCESS) {
		if (response)
			free(response);
		if (ret == PAM_BUF_ERR)
			errorx(pamh, params, "Possible malicious attempt, PAM_BUF_ERR.");
		return ret;
	}

	if (response) {
		strncpy(response_buf, response, MAX_BUF_SIZE);
		free(response);
		if (response_buf[MAX_BUF_SIZE - 1] != '\0' ) {
			errorx(pamh, params, "Possible malicious attempt, response way too long.");
			return PAM_AUTH_ERR;
		}
		if (params->time_limit) {
			clock_gettime(CLOCK_MONOTONIC, &completed_time);
			if (completed_time.tv_sec > sent_time.tv_sec + params->time_limit) {
				errorx(pamh, params, "took too long to respond, token expired");
				return PAM_AUTH_ERR;
			}
		}
		if (params->ignore_spaces)
			delete_spaces_inplace(response_buf);
		return PAM_SUCCESS;
	}
	return PAM_CONV_ERR;
}

bool is_spacefree(char *str)
{
	if (!str)
		return true;
	while (*str) {
		if (*str++ == ' ')
			return false;
	}
	return true;
}

int parse_args(pam_handle_t *pamh, Params *params, int argc, const char **argv)
{
	int c;
	int idx = -1;
	opterr = 0; /* global, tells getopt to not print any errors */
	while (1) {
		static const char optstring[] = "+nNpsdIDa:t:C:T:";
		static struct option options[] = {
			{"nullok",		0, 0, 'n'},
			{"nonull",		0, 0, 'N'},
			{"nostrictpermissions", 0, 0, 'p'},
			{"silent",		0, 0, 's'},
			{"debug",		0, 0, 'd'},
			{"ignore-spaces",	0, 0, 'I'},
			{"dbus",		0, 0, 'D'},
			{"add-space-every",	1, 0, 'a'},
			{"time-limit",		1, 0, 't'},
			{"allowed-chars",	1, 0, 'C'},
			{"token-len",		1, 0, 'T'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, (char * const *)argv, optstring, options, &idx);
		if (c > 0) {
			for (size_t i = 0; options[i].name; i++) {
				if (options[i].val == c) {
					idx = i;
					break;
				}
			}
		} else if (c < 0) {
			break;
		}
		if (idx < 0) {
			errorx(pamh, NULL, "error processing arguments, aborting");
			return PAM_AUTH_ERR;
		} else if (!idx--) { /* nullok */
			params->nullok = true;
		} else if (!idx--) { /* nonull */
			params->nullok = false;
		} else if (!idx--) { /* nostrictpermissions */
			params->strict_permissions = false;
		} else if (!idx--) { /* silent */
			params->silent = true;
		} else if (!idx--) { /* debug */
			params->silent = false;
		} else if (!idx--) { /*ignore-spaces */
			params->ignore_spaces = true;
			if (!is_spacefree(params->allowed_chars)) {
				errorx(pamh, NULL, "cannot ignore spaces if space is an allowed token character, aborting");
				return PAM_AUTH_ERR;
			}
		} else if (!idx--) { /* dbus */
			params->use_dbus = true;
		} else if (!idx--) { /* add-space-every */
			params->add_space_every = (size_t)atoi(optarg);
			params->ignore_spaces = true;
			if (!is_spacefree(params->allowed_chars)) {
				errorx(pamh, NULL, "cannot add spaces if space is an allowed token character, aborting");
				return PAM_AUTH_ERR;
			}
		} else if (!idx--) { /* time-limit */
			params->time_limit = (time_t)atoi(optarg);
			if (params->time_limit > 3600) {
				errorx(pamh, NULL, "allowed time to login is more than an hour, too long, aborting");
				return PAM_AUTH_ERR;
			}
		} else if (!idx--) { /* allowed-chars */
			strncpy(params->allowed_chars, optarg, 255);
			params->allowed_chars[255] = '\0';
			if (params->ignore_spaces && !is_spacefree(params->allowed_chars)) {
				errorx(pamh, NULL, "cannot ignore spaces if space is an allowed token character, aborting");
				return PAM_AUTH_ERR;
			}
			size_t n = strlen(params->allowed_chars);
			params->allowed_chars_len = n;
			if (n < 8) {
				errorx(pamh, NULL, "allowed-chars is too short, must be at least 8 characters, aborting");
				return PAM_AUTH_ERR;
			} else if (256 % n != 0) {
				errorx(pamh, NULL, "allowed-chars: %s\nlength: %zu\nlength must be a divisor of 256, aborting", params->allowed_chars, n);
				return PAM_AUTH_ERR;
			}
		} else if (!idx--) { /* token-len */
			size_t len = (size_t)atoi(optarg);
			if (len > MAX_TOKEN_LEN) {
				errorx(pamh, NULL, "invalid token length: %zu", len);
				return PAM_AUTH_ERR;
			}
			params->token_len = len;
		} else {
			errorx(pamh, NULL, "error processing command line arguments, aborting");
			return PAM_AUTH_ERR;
		}
	}
	if (optind != argc) {
		errorx(pamh, NULL, "Non-option argument given, did you forget --? Aborting");
		return PAM_AUTH_ERR;
	}

	if (!params->allowed_chars || !params->allowed_chars[0]) {
		params->allowed_chars = ALLOWED_CHARS_DEFAULT;
		params->allowed_chars_len = ALLOWED_CHARS_LEN_DEFAULT;
	}

	int bits = bits_of_entropy(params->token_len, params->allowed_chars_len);
	if (bits < MINIMUM_BITS_OF_ENTROPY) {
		errorx(pamh, NULL, "Only %i bits of entropy per token, increase length or allow more characters, aborting", bits);
		return PAM_AUTH_ERR;
	}
	return PAM_SUCCESS;
}

/*
 * This is the entry point, think of it as main().
 * PAM entry point for authentication verification
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int ret;
	char allowed_chars[256] = {0};
	char *recipients_arr[MAX_RECIPIENTS] = {0};

	Params params_s = {
		.nullok = !(flags & PAM_DISALLOW_NULL_AUTHTOK),
		.strict_permissions = true,
		.silent = flags & PAM_SILENT,
		.ignore_spaces = false,
		.use_dbus = false,
		.time_limit = 0,
		.allowed_chars = allowed_chars,
		.allowed_chars_len = 0,
		.token_len = TOKEN_LEN,
		.add_space_every = 0
	};
	Params *params = &params_s;
	if ((ret = parse_args(pamh, params, argc, argv)) != PAM_SUCCESS)
		return ret;

	int NULL_FAILURE = params->nullok ? PAM_SUCCESS : PAM_AUTH_ERR;

	/* Determine the user */
	const char *user = NULL;
	if ((ret = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS || user == NULL) {
		errorx(pamh, params, "failed to get user");
		return ret;
	}

	/* Get the user's passwd info */
	struct passwd *pw = NULL;
	struct passwd pw_s;
	char passdw_char_buf[MAX_BUF_SIZE] = {0};
	ret = getpwnam_r(user, &pw_s, passdw_char_buf, sizeof(passdw_char_buf), &pw);
	if (ret != 0 || pw == NULL || pw->pw_dir == NULL || pw->pw_dir[0] != '/') {
		errorx(pamh, params, "failed to get passwd struct");
		return PAM_AUTH_ERR;
	}

	/* Get the signal-authenticator user's passwd info */
	struct passwd *signal_pw = NULL;
	struct passwd signal_pw_s;
	char signal_passdw_char_buf[MAX_BUF_SIZE] = {0};
	ret = getpwnam_r(SYSTEM_SIGNAL_USER, &signal_pw_s, signal_passdw_char_buf,
			sizeof(signal_passdw_char_buf), &signal_pw);
	if (ret != 0 || signal_pw == NULL || signal_pw->pw_dir == NULL || signal_pw->pw_dir[0] != '/') {
		errorx(pamh, params, "failed to get signal passwd struct");
		return PAM_AUTH_ERR;
	}

	/* Check that user wants 2 factor authentication */
	char config_filename_buf[MAX_BUF_SIZE] = {0};
	if (get_2fa_config_filename(pw->pw_dir, config_filename_buf) != PAM_SUCCESS) {
		errorx(pamh, params, "failed to get config filename");
		goto null_failure;
	}

	char signal_config_filename_buf[MAX_BUF_SIZE] = {0};
	if (get_2fa_config_filename(signal_pw->pw_dir, signal_config_filename_buf) != PAM_SUCCESS) {
		errorx(pamh, params, "failed to get signal-authenticator config filename");
		goto null_failure;
	}

	const char *config_filename = config_filename_buf;
	const char *signal_config_filename = signal_config_filename_buf;

	if (!configs_exist_permissions_good(pamh, params, pw, signal_pw, config_filename, signal_config_filename))
		goto null_failure;

	/*
	 * At this point we know the user must do 2fa,
	 * they either opted in by putting the config file where it should be
	 * or the sysadmin requires 2fa
	 * (though the user or admin may still have an invalid config file)
	 * from here on failures should err on the side of denying access
	 */

	char username_buf[MAX_USERNAME_LEN + 1] = {0};
	if (parse_signal_username(signal_config_filename, username_buf) != PAM_SUCCESS) {
		errorx(pamh, params, "Failed to parse sender username from config");
		goto cleanup_then_return_auth_err;
	}
	const char *username = username_buf;

	char token_buf[MAX_TOKEN_LEN + 1] = {0};
	if (generate_random_token(token_buf, params) != PAM_SUCCESS) {
		errorx(pamh, params, "failed to generate random token");
		goto cleanup_then_return_auth_err;
	}
	const char *token = token_buf;

	char message_buf[MAX_BUF_SIZE] = {0};
	if (make_message(params, token, message_buf) != PAM_SUCCESS) {
		errorx(pamh, params, "failed to make message from token");
		goto cleanup_then_return_auth_err;
	}
	const char *message = message_buf;

	if (parse_signal_recipients(config_filename, recipients_arr) != PAM_SUCCESS) {
		errorx(pamh, params, "Failed to parse recipients from config");
		goto cleanup_then_return_auth_err;
	}

	const char *signal_send_args_arr[4 + MAX_RECIPIENTS + 1] = {0};
	ret = build_signal_send_command(params, username, recipients_arr, signal_send_args_arr);
	if (ret != PAM_SUCCESS) {
		errorx(pamh, params, "Failed to build signal send command");
		goto cleanup_then_return_auth_err;
	}
	char * const * signal_send_args = (char * const *)signal_send_args_arr;

	if (!params->use_dbus) {
		const char *signal_receive_args_arr[8];
		if (build_signal_receive_command(username, signal_receive_args_arr) != PAM_SUCCESS) {
			errorx(pamh, params, "Failed to build signal receive command");
			goto cleanup_then_return_auth_err;
		}

		char * const * signal_receive_args = (char * const *)signal_receive_args_arr;
		if (signal_cli(pamh, params, signal_pw, signal_receive_args, NULL) != PAM_SUCCESS) {
			errorx(pamh, params, "signal-cli receive command failed");
			goto cleanup_then_return_auth_err;
		}
	}

	if (signal_cli(pamh, params, signal_pw, signal_send_args, message) != PAM_SUCCESS) {
		errorx(pamh, params, "signal-cli send command failed");
		goto cleanup_then_return_auth_err;
	}

	char response_buf[MAX_BUF_SIZE] = {0};
	if (wait_for_response(pamh, params, response_buf) != PAM_SUCCESS) {
		errorx(pamh, params, "failed response");
		goto cleanup_then_return_auth_err;
	}
	const char *response = response_buf;
	if (strlen(response) != params->token_len || strncmp(response, token, params->token_len) != 0) {
		errorx(pamh, params, "incorrect token");
		goto cleanup_then_return_auth_err;
	}

	free_str_array(recipients_arr, MAX_RECIPIENTS);
	return PAM_SUCCESS;

null_failure:
	if (params->nullok)
		pam_info(pamh, "Authenticated fully. User has not enabled two-factor authentication.");
	return NULL_FAILURE;
cleanup_then_return_auth_err:
	free_str_array(recipients_arr, MAX_RECIPIENTS);
	return PAM_AUTH_ERR;
}

/*
 * These PAM entry points are not used in signal-authenticator
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

/* PAM entry point for session creation */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

/* PAM entry point for session cleanup */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

/* PAM entry point for accounting */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

/*
 * PAM entry point for setting user credentials (that is, to actually
 * establish the authenticated user's credentials to the service provider)
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

/* PAM entry point for authentication token (password) changes */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_IGNORE;
}

#pragma GCC diagnostic pop
