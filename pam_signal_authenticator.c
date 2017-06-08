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

#define VERSION "0.1"
#define MODULE_NAME "pam_signal_authenticator.so"
#ifndef SIGNAL_CLI
#define SIGNAL_CLI "/usr/local/bin/signal-cli"
#endif
#define SIGNAL_CLI_LEN ((sizeof(SIGNAL_CLI)/sizeof(SIGNAL_CLI[0]))-1)
#ifndef MAX_BUF_SIZE
#define MAX_BUF_SIZE 1024
#endif
#ifndef TOKEN_LEN
#define TOKEN_LEN 13
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

/*
 * signal-cli is called using system(), so DO NOT allow escape characters,
 * quotes, semicolons, etc. unless you sanitize the system call
 *
 * allowed chars length should be a factor of 256, suggested 32 or higher
 */
#ifndef ALLOWED_CHARS
#define ALLOWED_CHARS "abcdefghijkmnpqrstuvwxyz12345678"
#endif
#define ALLOWED_CHARS_LEN ((sizeof(ALLOWED_CHARS)/sizeof(ALLOWED_CHARS[0]))-1)


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
    bool timed;
} Params;

void error(pam_handle_t *pamh, const Params *params, const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    if (!params->silent)
        pam_vsyslog(pamh, LOG_ERR, msg, ap);
    va_end(ap);
}

void free_str_array(char *ptr[], size_t len) {
    for (size_t i=0; i<len; i++) {
        if (ptr[i]) {
            free(ptr[i]);
        }
    }
}

int get_2fa_config_filename(const char* home_dir, char fn_buf[MAX_BUF_SIZE]) {
    if (home_dir == NULL || fn_buf == NULL) {
        return PAM_AUTH_ERR;
    }
    size_t buf_size = sizeof(char[MAX_BUF_SIZE]);
    int snp_ret = snprintf(fn_buf, buf_size,
            "%s/"CONFIG_FILE, home_dir);
    if (snp_ret < 0 || (size_t)snp_ret >= buf_size) {
        return PAM_AUTH_ERR;
    }
    return PAM_SUCCESS;
}

int make_message(const char *token, char message_buf[MAX_BUF_SIZE]) {
    if (token == NULL || message_buf == NULL) {
        return PAM_AUTH_ERR;
    }
    size_t buf_size = sizeof(char[MAX_BUF_SIZE]);
    int snp_ret = snprintf(message_buf, buf_size,
            "%s%s%s", SIGNAL_MESSAGE_PREFIX, token, SIGNAL_MESSAGE_SUFFIX);
    if (snp_ret < 0 || (size_t)snp_ret >= buf_size) {
        return PAM_AUTH_ERR;
    }
    return PAM_SUCCESS;
}

int configs_exist_permissions_good(
        pam_handle_t *pamh,
        const Params *params,
        struct passwd *pw,
        struct passwd *signal_pw,
        const char *config_filename,
        const char *signal_config_filename) {
    struct stat s = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, {0, 0}, {0, 0}, {0, 0}, {0}};
    int result = stat(config_filename, &s);
    if (result < 0) {/* if file does not exist or something else fails */
        return false;
    }
    if (params->strict_permissions) {
        if (s.st_uid != pw->pw_uid) {
            error(pamh, params, "User uid=%d, but config uid=%d", pw->pw_uid, s.st_uid);
            return false;
        }
        if (s.st_gid != pw->pw_gid) {
            error(pamh, params, "User gid=%d, but config gid=%d", pw->pw_gid, s.st_gid);
            return false;
        }
        if ((s.st_mode & S_IROTH) || (s.st_mode & S_IWOTH) || (s.st_mode & S_IXOTH)) {
            error(pamh, params, "config has bad permissions, try chmod o-rwx");
            return false;
        }
    }

    result = stat(signal_config_filename, &s);
    if (result < 0) {
        return false;
    }
    // nostrictpermissions does not apply to the admin
    if (s.st_uid != signal_pw->pw_uid || s.st_gid != signal_pw->pw_gid) {
        error(pamh, params, "signal-authenticator uid=%d, but config uid=%d",
                    signal_pw->pw_uid, s.st_uid);
        return false;
    }
    if ((s.st_mode & S_IROTH) || (s.st_mode & S_IWOTH) || (s.st_mode & S_IXOTH)) {
        error(pamh, params, "signal-authenticator config has bad permissions, try chmod o-rwx");
        return false;
    }
    return true;
}

int drop_privileges(struct passwd *pw) {
    int gid_ret = setgid(pw->pw_gid);
    int uid_ret = setuid(pw->pw_uid);
    if (uid_ret != 0 || gid_ret != 0) {
        return PAM_AUTH_ERR;
    }
    return PAM_SUCCESS;
}

// Will be TOKEN_LEN many characters from ALLOWED_CHARS
// Result is uniform string in ALLOWED_CHARS as long as
// ALLOWED_CHARS_LEN is a divisor of 256
int generate_random_token(char token_buf[TOKEN_LEN+1]) {
    FILE *urandom = fopen("/dev/urandom", "r");
    if (urandom == NULL) {
        return PAM_AUTH_ERR;
    }
    unsigned char c;
    for (size_t i = 0; i < TOKEN_LEN; i++) {
        c = fgetc(urandom);
        token_buf[i] = ALLOWED_CHARS[c % ALLOWED_CHARS_LEN];
    }
    token_buf[TOKEN_LEN] = '\0';
    if (fclose(urandom) != 0) {
        return PAM_AUTH_ERR;
    }
    return PAM_SUCCESS;
}

bool looks_like_phone_number(const char *str) {
    if (str == NULL) {
        return false;
    }
    int len = strlen(str);
    if (len == 0 || len > MAX_USERNAME_LEN) {
        return false;
    }
    while (*str) {
        if (!(*str == '+' || ('0' <= *str && *str <= '9'))) {
            return false;
        }
        str++;
    }
    return true;
}

int parse_signal_username(const char *config_filename, char username_buf[MAX_USERNAME_LEN+1]) {
    FILE *config_fp = fopen(config_filename, "r");
    if (config_fp == NULL) {
        return PAM_AUTH_ERR;
    }

    bool username_found = false;
    char line_buf[MAX_BUF_SIZE] = {0};
    while (!username_found && fgets(line_buf, sizeof(line_buf), config_fp) != NULL) {
        int len = strlen(line_buf);
        if (line_buf[len-1] != '\n') {
           return PAM_AUTH_ERR;
        }
        line_buf[len-1] = '\0';
        const char *line = line_buf;
        switch (*line) {
            // Comment or empty line?
            case '#':
            case '\0':
                break;
            // username
            case 'u':
                if (strncmp(line, "username=", strlen("username=")) != 0) {
                    goto error;
                }
                line += strlen("username=");
                if (looks_like_phone_number(line)) {
                    // it is known here that strlen(line) <= MAX_USERNAME_LEN
                    strncpy(username_buf, line, MAX_USERNAME_LEN+1);
                    username_found = true;
                }
                else {
                    goto error;
                }
                break;
            // ignore garbage
            default:
                break;
        }
    }
    if (fclose(config_fp) != 0 || !username_found) {
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;

    error: {
        fclose(config_fp);
        return PAM_AUTH_ERR;
    }
}

int parse_signal_recipients(const char *config_filename, char *recipients_arr[MAX_RECIPIENTS]){
    FILE *config_fp = fopen(config_filename, "r");
    if (config_fp == NULL) {
        return PAM_AUTH_ERR;
    }

    int recipient_count = 0;
    char line_buf[MAX_BUF_SIZE] = {0};
    while (fgets(line_buf, sizeof(line_buf), config_fp) != NULL) {
        int len = strlen(line_buf);
        if (line_buf[len -1] != '\n') {
           return PAM_AUTH_ERR;
        }
        line_buf[len-1] = '\0';
        const char *line = line_buf;
        switch (*line) {
            // Comment or empty line?
            case '#':
            case '\0':
                break;
            // recipient
            case 'r':
                if (strncmp(line, "recipient=", strlen("recipient=")) != 0) {
                    goto error;
                }
                line += strlen("recipient=");
                if (looks_like_phone_number(line)) {
                    int username_len = strlen(line);
                    recipients_arr[recipient_count] = calloc(username_len+1, sizeof(char));
                    if (!recipients_arr[recipient_count]) {
                        goto error;
                    }
                    strcpy(recipients_arr[recipient_count++], line);
                }
                else {
                    goto error;
                }
                break;
            default:
                break;
        }
        // if the user specified more than MAX_RECIPIENTS recipients, just use
        // the first few
        if (recipient_count == MAX_RECIPIENTS) {
            break;
        }
    }
    if (fclose(config_fp) != 0 || recipient_count == 0) {
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;

    error: {
        fclose(config_fp);
        return PAM_AUTH_ERR;
    }
}

int build_signal_send_command(
        const char *sender,
        char *recipients[MAX_RECIPIENTS],
        const char *message,
        const char *args[6+MAX_RECIPIENTS+1]) {
    if (sender == NULL || recipients == NULL || message == NULL || args == NULL) {
        return PAM_AUTH_ERR;
    }
    args[0] = "signal-cli";
    args[1] = "-u";
    args[2] = sender;
    args[3] = "send";
    args[4] = "-m";
    args[5] = message;
    for (size_t i = 6; i < 6+MAX_RECIPIENTS; i++) {
        if (recipients[i-6] && recipients[i-6][0]) {
            args[i] = recipients[i-6];
        }
        else {
            args[i] = (const char *)NULL;
            break;
        }
    }
    args[6+MAX_RECIPIENTS] = (const char *)NULL;
    return PAM_SUCCESS;
}

int build_signal_receive_command(
        const char *username,
        const char *args[8]) {
    if (username == NULL || args == NULL) {
        return PAM_AUTH_ERR;
    }
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
        struct passwd *drop_pw, char *const argv[]) {
    pid_t c_pid;
    int status;

    c_pid = fork();

    if (c_pid == 0) {
        // child
        if (drop_privileges(drop_pw) != PAM_SUCCESS ) {
            exit(EXIT_FAILURE);
        }
        int fdnull = open("/dev/null", O_RDWR);
        if (fdnull) {
            bool failure = false;
            failure |= dup2(fdnull, STDIN_FILENO) < 0;
            failure |= dup2(fdnull, STDOUT_FILENO) < 0;
            failure |= dup2(fdnull, STDERR_FILENO) < 0;
            if (close(fdnull) != 0 || failure) {
                exit(EXIT_FAILURE);
            }
        }
        else {
            exit(EXIT_FAILURE);
        }
        execv(SIGNAL_CLI, argv);
    }
    else if (c_pid <  0) {
        error(pamh, params, "failed to fork child for sending message");
        return PAM_AUTH_ERR;
    }
    // parent
    wait(&status);

    if(!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
}

int wait_for_response(pam_handle_t *pamh, const Params *params, char response_buf[MAX_BUF_SIZE]) {
    char *response = NULL;
    int ret = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &response, SSH_PROMPT);
    if (ret != PAM_SUCCESS) {
        if (response) {
            free(response);
        }
        if (ret == PAM_BUF_ERR) {
            error(pamh, params, "Possible malicious attempt, PAM_BUF_ERR.");
        }
        return ret;
    }

    if (response) {
        strncpy(response_buf, response, MAX_BUF_SIZE);
        free(response);
        if (response_buf[MAX_BUF_SIZE-1] != '\0' ) {
            error(pamh, params, "Possible malicious attempt, response way too long.");
            return PAM_AUTH_ERR;
        }
        return PAM_SUCCESS;
    }
    return PAM_CONV_ERR;
}

// This is the entry point, think of it as main()
/* PAM entry point for authentication verification */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {

    int ret;
    Params params_s = {
        .nullok = !(flags & PAM_DISALLOW_NULL_AUTHTOK),
        .strict_permissions = true,
        .silent = flags & PAM_SILENT,
        .timed = false
    };
    Params *params = &params_s;

    while (argc > 0) {
        const char *arg = *argv;
        if (strcmp(arg, "nullok") == 0) {
            params->nullok = true;
        }
        else if (strcmp(arg, "nonull") == 0) {
            params->nullok = false;
        }
        else if (strcmp(arg, "nostrictpermissions") == 0) {
            params->strict_permissions = false;
        }
        else if (strcmp(arg, "silent") == 0) {
            params->silent = true;
        }
        else if (strcmp(arg, "debug") == 0) {
            params->silent = false;
        }
        else if (strcmp(arg, "timed") == 0) {
            params->timed = true;
        }
        else {
            pam_syslog(pamh, LOG_ERR, "Aborting due to unknown option: %s", arg);
            return PAM_AUTH_ERR;
        }
        argc--;
        argv++;
    }
    int NULL_FAILURE = params->nullok? PAM_SUCCESS : PAM_AUTH_ERR;

    //determine the user
    const char *user = NULL;
    if ((ret = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS || user == NULL) {
        error(pamh, params, "failed to get user");
        return ret;
    }

    //get the user and signal-authenticator's passwd info
    struct passwd *pw = NULL;
    struct passwd pw_s;
    char passdw_char_buf[MAX_BUF_SIZE] = {0};
    struct passwd *signal_pw = NULL;
    struct passwd signal_pw_s;
    char signal_passdw_char_buf[MAX_BUF_SIZE] = {0};
    ret = getpwnam_r(user, &pw_s, passdw_char_buf, sizeof(passdw_char_buf), &pw);
    if (ret != 0 || pw == NULL || pw->pw_dir == NULL || pw->pw_dir[0] != '/') {
        error(pamh, params, "failed to get passwd struct");
        return PAM_AUTH_ERR;
    }
    ret = getpwnam_r(SYSTEM_SIGNAL_USER, &signal_pw_s, signal_passdw_char_buf,
            sizeof(signal_passdw_char_buf), &signal_pw);
    if (ret != 0 || signal_pw == NULL || signal_pw->pw_dir == NULL || signal_pw->pw_dir[0] != '/') {
        error(pamh, params, "failed to get signal passwd struct");
        return PAM_AUTH_ERR;
    }

    // check that user wants 2 factor authentication
    char config_filename_buf[MAX_BUF_SIZE] = {0};
    if (get_2fa_config_filename(pw->pw_dir, config_filename_buf) != PAM_SUCCESS) {
        error(pamh, params, "failed to get config filename");
        goto null_failure;
    }

    char signal_config_filename_buf[MAX_BUF_SIZE] = {0};
    if (get_2fa_config_filename(signal_pw->pw_dir, signal_config_filename_buf) != PAM_SUCCESS) {
        error(pamh, params, "failed to get signal-authenticator config filename");
        goto null_failure;
    }

    const char *config_filename = config_filename_buf;
    const char *signal_config_filename = signal_config_filename_buf;

    if (!configs_exist_permissions_good(pamh, params, pw, signal_pw, config_filename, signal_config_filename)) {
        goto null_failure;
    }

    // at this point we know the user must do 2fa,
    // they either opted in by putting the config file where it should be
    // or the sysadmin requires 2fa
    // (though the user or admin may still have an invalid config file)
    // from here on failures should err on the side of denying access
    
    char username_buf[MAX_USERNAME_LEN+1] = {0};
    if (parse_signal_username(signal_config_filename, username_buf) != PAM_SUCCESS) {
        error(pamh, params, "Failed to parse sender username from config");
        goto cleanup_then_return_error;
    }
    const char *username = username_buf;

    char token_buf[TOKEN_LEN+1] = {0};
    if (generate_random_token(token_buf) != PAM_SUCCESS) {
        error(pamh, params, "failed to generate random token");
        goto cleanup_then_return_error;
    }
    const char *token = token_buf;

    char message_buf[MAX_BUF_SIZE] = {0};
    if (make_message(token, message_buf) != PAM_SUCCESS) {
        error(pamh, params, "failed to make message from token");
        goto cleanup_then_return_error;
    }
    const char *message = message_buf;

    char *recipients_arr[MAX_RECIPIENTS] = {0};
    if (parse_signal_recipients(config_filename, recipients_arr) != PAM_SUCCESS) {
        error(pamh, params, "Failed to parse recipients from config");
        goto cleanup_then_return_error;
    }

    const char *signal_send_args_arr[6+MAX_RECIPIENTS+1] = {0};
    ret = build_signal_send_command(username, recipients_arr, message, signal_send_args_arr);
    if (ret != PAM_SUCCESS) {
        error(pamh, params, "Failed to build signal send command");
        goto cleanup_then_return_error;
    }
    char * const * signal_send_args = (char * const *)signal_send_args_arr;

    const char *signal_receive_args_arr[8];
    if (build_signal_receive_command(username, signal_receive_args_arr) != PAM_SUCCESS) {
        error(pamh, params, "Failed to build signal receive command");
        goto cleanup_then_return_error;
    }

    char * const * signal_receive_args = (char * const *)signal_receive_args_arr;
    if (signal_cli(pamh, params, signal_pw, signal_receive_args) != PAM_SUCCESS) {
        error(pamh, params, "signal-cli receive command failed");
        goto cleanup_then_return_error;
    }

    struct timespec sent_time, completed_time;
    if (params->timed) {
        clock_gettime(CLOCK_MONOTONIC, &sent_time);
        pam_info(pamh, "Token expires in %i seconds.", TOKEN_TIME_TO_EXPIRE);
    }

    if (signal_cli(pamh, params, signal_pw, signal_send_args) != PAM_SUCCESS) {
        error(pamh, params, "signal-cli send command failed");
        goto cleanup_then_return_error;
    }
    
    char response_buf[MAX_BUF_SIZE] = {0};
    if (wait_for_response(pamh, params, response_buf) != PAM_SUCCESS) {
        error(pamh, params, "failed response");
        goto cleanup_then_return_error;
    }
    const char *response = response_buf;

    if(params-> timed) {
        clock_gettime(CLOCK_MONOTONIC, &completed_time);
        if (completed_time.tv_sec > sent_time.tv_sec + TOKEN_TIME_TO_EXPIRE) {
            error(pamh, params, "took too long to respond, token expired");
            goto cleanup_then_return_error;
        }
    }

    if(strlen(response) != TOKEN_LEN || strncmp(response, token, TOKEN_LEN) != 0) {
        error(pamh, params, "incorrect token");
        goto cleanup_then_return_error;
    }

    free_str_array(recipients_arr, MAX_RECIPIENTS);
    return PAM_SUCCESS;

    null_failure : {
        if (params->nullok) {
            pam_info(pamh, "Authenticated fully. User has not enabled two-factor authentication.");
        }
        return NULL_FAILURE;
    }

    cleanup_then_return_error : {
        free_str_array(recipients_arr, MAX_RECIPIENTS);
        return PAM_AUTH_ERR;
   }
}

/*
 * These PAM entry points are not used in signal-authenticator
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

/* PAM entry point for session creation */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

/* PAM entry point for session cleanup */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

/* PAM entry point for accounting */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

/*
 PAM entry point for setting user credentials (that is, to actually
 establish the authenticated user's credentials to the service provider)
*/
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

/* PAM entry point for authentication token (password) changes */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

#pragma GCC diagnostic pop
