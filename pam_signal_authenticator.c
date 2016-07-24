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
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/wait.h>

#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#define MODULE_NAME "pam_signal_authenticator.so"
#ifndef SIGNAL_CLI
#define SIGNAL_CLI "/usr/local/bin/signal-cli"
#endif
#define SIGNAL_CLI_LEN ((sizeof(SIGNAL_CLI)/sizeof(SIGNAL_CLI[0]))-1)
#ifndef MAX_BUF_SIZE
#define MAX_BUF_SIZE 1024
#endif
#ifndef TOKEN_LEN
#define TOKEN_LEN 10
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
 */
#ifndef ALLOWED_CHARS
#define ALLOWED_CHARS "abcdefghijklmnopqrstuvwxyz"
#endif
#define ALLOWED_CHARS_LEN ((sizeof(ALLOWED_CHARS)/sizeof(ALLOWED_CHARS[0]))-1)

typedef struct params {
    bool nullok;
    bool strict_permissions;
    bool use_system_user;
    bool silent;
} Params;

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
        if (s.st_uid != pw->pw_uid ) {
            if (!params->silent)
                pam_syslog(pamh, LOG_ERR, "User uid=%d, but config uid=%d", pw->pw_uid, s.st_uid);
            return false;
        }
        if (s.st_gid != pw->pw_gid ) {
            if (!params->silent)
                pam_syslog(pamh, LOG_ERR, "User gid=%d, but config gid=%d", pw->pw_gid, s.st_gid);
            return false;
        }
        if ((s.st_mode & S_IROTH) || (s.st_mode & S_IWOTH) || (s.st_mode & S_IXOTH)) {
            if (!params->silent)
                pam_syslog(pamh, LOG_ERR, "config has bad permissions, try chmod o-rwx");
            return false;
        }
    }
    if (params->use_system_user) {
        result = stat(signal_config_filename, &s);
        if (result < 0) {
            return false;
        }
        // nostrictpermissions does not apply to the admin
        if (s.st_uid != signal_pw->pw_uid || s.st_gid != signal_pw->pw_gid) {
            if (!params->silent) {
                pam_syslog(pamh, LOG_ERR, "signal-authenticator uid=%d, but config uid=%d",
                        signal_pw->pw_uid, s.st_uid);
            }
            return false;
        }
        if ((s.st_mode & S_IROTH) || (s.st_mode & S_IWOTH) || (s.st_mode & S_IXOTH)) {
            if (!params->silent)
                pam_syslog(pamh, LOG_ERR, "signal-authenticator config has bad permissions, try chmod o-rwx");
            return false;
        }
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

// token will match [a-z]{TOKEN_LEN}
int generate_random_token(char token_buf[TOKEN_LEN+1]) {
    FILE *urandom = fopen("/dev/urandom", "r");
    if (urandom == NULL) {
        return PAM_AUTH_ERR;
    }
    unsigned char c;
    for(int i = 0; i < TOKEN_LEN; i++) {
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
    if (len == 0 || len > 20){
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

int parse_signal_username(const char *config_filename, char username_buf[MAX_BUF_SIZE]) {
    FILE *config_fp = fopen(config_filename, "r");
    if (config_fp == NULL) {
        return PAM_AUTH_ERR;
    }

    bool username_found = false;
    char line_buf[MAX_BUF_SIZE] = {0};
    while (fgets(line_buf, sizeof(line_buf), config_fp) != NULL) {
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
                    strncpy(username_buf, line, strlen(line));
                    username_found = true;
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

int parse_signal_recipients(const char *config_filename, char recipients_buf[MAX_BUF_SIZE]){
    FILE *config_fp = fopen(config_filename, "r");
    if (config_fp == NULL) {
        return PAM_AUTH_ERR;
    }

    int recipient_count = 0;
    int recipients_strlen = 0;
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
                    int recipient_len = strlen(line);
                    int new_strlen = recipient_len + recipients_strlen + 1;
                    // too many recipients?
                    if (new_strlen+1 >= MAX_BUF_SIZE) {
                        goto error;
                    }
                    strcpy(recipients_buf+recipients_strlen, line);
                    recipients_buf[new_strlen-1] = ' ';
                    recipients_strlen = new_strlen;
                    recipient_count++;
                }
                break;
            default:
                break;
        }
    }
    if (fclose(config_fp) != 0 || recipient_count == 0) {
        return PAM_AUTH_ERR;
    }

    recipients_buf[recipients_strlen-1] = '\0';

    return PAM_SUCCESS;

    error: {
        fclose(config_fp);
        return PAM_AUTH_ERR;
    }
}

int build_signal_command(
        pam_handle_t *pamh,
        const Params *params,
        const char *config_filename,
        const char *signal_config_filename,
        const char *token,
        char signal_cmd_buf[MAX_BUF_SIZE]) {
    int ret;
    char username_buf[MAX_BUF_SIZE] = {0};

    const char * fn = params->use_system_user? signal_config_filename : config_filename;
    if ((ret = parse_signal_username(fn, username_buf)) != PAM_SUCCESS) {
        if (!params->silent)
            pam_syslog(pamh, LOG_ERR, "Failed to parse username from config");
        return PAM_AUTH_ERR;
    }
    const char *username = username_buf;

    char recipients_buf[MAX_BUF_SIZE] = {0};
    if ((ret = parse_signal_recipients(config_filename, recipients_buf)) != PAM_SUCCESS) {
        if (!params->silent)
            pam_syslog(pamh, LOG_ERR, "Failed to parse recipients from config");
        return PAM_AUTH_ERR;
    }
    const char *recipients = recipients_buf;

    ret = snprintf(signal_cmd_buf, MAX_BUF_SIZE,
            "%s -u %s send -m '%s' %s >/dev/null 2>&1 &&"
            "%s -u %s receive >/dev/null 2>&1 &",
            SIGNAL_CLI, username, token, recipients,
            SIGNAL_CLI, username);
    if (ret < 0 || (size_t)ret >= sizeof(char[MAX_BUF_SIZE])) {
        if (!params->silent)
            pam_syslog(pamh, LOG_ERR, "Failed to snprintf the signal command");
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
}

int send_signal_msg_and_wait_for_response(pam_handle_t *pamh, const Params *params,
        struct passwd *drop_pw, const char *signal_cmd, char response_buf[MAX_BUF_SIZE]) {
    int ret;
    pid_t c_pid;
    int status;

    c_pid = fork();

    if (c_pid == 0) {
        // child
        if ((ret = drop_privileges(drop_pw)) != PAM_SUCCESS ) {
            exit(EXIT_FAILURE);
        }
        // send the actual signal message
        exit(system(signal_cmd));
    }
    else if (c_pid <  0) {
        // error
        if (!params->silent)
            pam_syslog(pamh, LOG_ERR, "failed to fork child for sending message");
        return PAM_AUTH_ERR;
    }
    // parent
    wait(&status);

    if(!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
        return PAM_AUTH_ERR;
    }

    char *response = NULL;
    ret = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &response, "1-time code: ");
    if (ret != PAM_SUCCESS) {
        if (ret == PAM_BUF_ERR && !params->silent){
            pam_syslog(pamh, LOG_ERR, "Possible malicious attempt, PAM_BUF_ERR.");
        }
        return ret;
    }

    if (response) {
        strncpy(response_buf, response, MAX_BUF_SIZE);
        free(response);
        if (response_buf[MAX_BUF_SIZE-1] != '\0' ) {
            if (!params->silent)
                pam_syslog(pamh, LOG_ERR, "Possible malicious attempt, response way too long.");
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
        .use_system_user = true,
        .silent = flags & PAM_SILENT
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
        else if (strcmp(arg, "systemuser") == 0) {
            params->use_system_user = true;
        }
        else if (strcmp(arg, "nosystemuser") == 0) {
            params->use_system_user = false;
        }
        else if (strcmp(arg, "silent") == 0) {
            params->silent = true;
        }
        else if (strcmp(arg, "debug") == 0) {
            params->silent = false;
        }
        argc--;
        argv++;
    }
    int NULL_FAILURE = params->nullok? PAM_SUCCESS : PAM_AUTH_ERR;

    //determine the user
    const char *user = NULL;
    if ((ret = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS || user == NULL) {
        if (!params->silent) {
            pam_syslog(pamh, LOG_ERR, "failed to get user");
        }
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
        if (!params->silent)
            pam_syslog(pamh, LOG_ERR, "failed to get passwd struct");
        return PAM_AUTH_ERR;
    }
    ret = getpwnam_r(SYSTEM_SIGNAL_USER, &signal_pw_s, signal_passdw_char_buf,
            sizeof(signal_passdw_char_buf), &signal_pw);
    if (ret != 0 || signal_pw == NULL || signal_pw->pw_dir == NULL || signal_pw->pw_dir[0] != '/') {
        if (!params->silent)
            pam_syslog(pamh, LOG_ERR, "failed to get signal passwd struct");
        return PAM_AUTH_ERR;
    }

    // check that user wants 2 factor authentication
    char config_filename_buf[MAX_BUF_SIZE] = {0};
    if (get_2fa_config_filename(pw->pw_dir, config_filename_buf) != PAM_SUCCESS) {
        if (!params->silent)
            pam_syslog(pamh, LOG_ERR, "failed to get config filename");
        goto null_failure;
    }

    char signal_config_filename_buf[MAX_BUF_SIZE] = {0};
    if (params->use_system_user && get_2fa_config_filename(signal_pw->pw_dir, signal_config_filename_buf) != PAM_SUCCESS) {
        if (!params->silent)
            pam_syslog(pamh, LOG_ERR, "failed to get signal-authenticator config filename");
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

    char token_buf[TOKEN_LEN+1] = {0};
    if ((ret = generate_random_token(token_buf)) != PAM_SUCCESS) {
        if (!params->silent)
            pam_syslog(pamh, LOG_ERR, "failed to generate random token");
        return ret;
    }
    const char *token = token_buf;

    char signal_cmd_buf[MAX_BUF_SIZE] = {0};
    ret = build_signal_command(pamh, params, config_filename, signal_config_filename, token, signal_cmd_buf);
    if (ret != PAM_SUCCESS) {
        if (!params->silent)
            pam_syslog(pamh, LOG_ERR, "failed to build signal command");
        return ret;
    }
    const char *signal_cmd = signal_cmd_buf;

    // who should we drop privileges to before calling external programs?
    struct passwd *drop_pw = params->use_system_user? signal_pw : pw;

    char response_buf[MAX_BUF_SIZE] = {0};
    ret = send_signal_msg_and_wait_for_response(pamh, params, drop_pw, signal_cmd, response_buf);
    if (ret != PAM_SUCCESS) {
        if (!params->silent)
            pam_syslog(pamh, LOG_ERR, "failed to send signal message or get response");
        return PAM_AUTH_ERR;
    }
    const char *response = response_buf;

    if(strlen(response) != TOKEN_LEN || strncmp(response, token, TOKEN_LEN) != 0) {
        if (!params->silent)
            pam_syslog(pamh, LOG_ERR, "incorrect token");
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;

    null_failure : {
        if (params->nullok) {
            pam_info(pamh, "Authenticated fully. User has not enabled two-factor authentication.");
        }
        return NULL_FAILURE;
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
