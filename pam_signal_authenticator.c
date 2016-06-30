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

#define PAM_SH_ACCOUNT
#define PAM_SH_AUTH
#define PAM_SH_PASSWORD
#define PAM_SH_SESSION

#include <pwd.h>
#include <sys/types.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>
#include <stdarg.h>

#define MAX_BUF_SIZE 1024
#define TOKEN_LEN 10
#define MODULE_NAME "pam_signal_authenticator.so"
#define CONFIG_FILE ".signal_authenticator"
#define ALLOWED_CHARS "abcdefghijklmnopqrstuvwxyz"
#define ALLOWED_CHARS_LEN ((sizeof(ALLOWED_CHARS)/sizeof(ALLOWED_CHARS[0]))-1)
#define SIGNAL_PROG_LEN ((sizeof(SIGNAL_PROG)/sizeof(SIGNAL_PROG[0]))-1)


// log_message function ripped from google-authenticator
// https://github.com/google/google-authenticator
// which came with the following license/copyright notice
//
// PAM module for two-factor authentication.
//
// Copyright 2010 Google Inc.
// Author: Markus Gutschke
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
void log_message(int priority, pam_handle_t *pamh,
                        const char *format, ...) {
    char *service = NULL;
    if (pamh) {
        pam_get_item(pamh, PAM_SERVICE, (void *)&service);
    }
    if (!service) {
        service = "";
    }
    char logname[80];
    snprintf(logname, sizeof(logname), "%s(" MODULE_NAME ")", service);

    va_list args;
    va_start(args, format);
    openlog(logname, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
    vsyslog(priority, format, args);
    closelog();
    va_end(args);

    if (priority == LOG_EMERG) {
        // Something really bad happened. There is no way we can proceed safely.
        _exit(1);
    }
}

/* PAM entry point for session creation */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

/* PAM entry point for session cleanup */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

/* PAM entry point for accounting */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}


int get_user(pam_handle_t *pamh, const char **user_ptr) {
    if (user_ptr == NULL) {
        return PAM_USER_UNKNOWN;
    }
    int pgu_ret = pam_get_user(pamh, user_ptr, NULL);
    if (pgu_ret != PAM_SUCCESS || *user_ptr == NULL) {
        return PAM_USER_UNKNOWN;
    }
    return PAM_SUCCESS;
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

int config_exists_permissions_good(uid_t uid, gid_t gid,
        const char *config_filename) {
      struct stat s = {0};
      int result = stat(config_filename, &s);
      if (result < 0) {/* if file does not exist or something else fails */
        return false;
      }
      if (s.st_uid == uid && s.st_gid == gid) { /* if uid and gid match */
          return true;
      }
      return false;
}

int drop_privileges(uid_t uid, gid_t gid) {
    int gid_ret = setgid(gid);
    int uid_ret = setuid(uid);
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

int build_signal_command(const char *config_filename, const char *token, 
        char signal_cmd_buf[MAX_BUF_SIZE]) {
    
    // see makefile for how SIGNAL_PROG gets expanded
    const char *signal_prog = SIGNAL_PROG;

    FILE *config_fp = fopen(config_filename, "r");
    if (config_fp == NULL) {
        return PAM_AUTH_ERR;
    }

    bool username_found = false;
    int recipient_count = 0;
    char username_buf[MAX_BUF_SIZE] = {0};
    const char *username = username_buf;
    char recipients_buf[MAX_BUF_SIZE] = {0};
    const char *recipients = recipients_buf;;
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
                goto error;
        }
    }
    if (fclose(config_fp) != 0 || !username_found || recipient_count == 0) {
        return PAM_AUTH_ERR;
    }

    recipients_buf[recipients_strlen-1] = '\0';
    int snp_ret = snprintf(signal_cmd_buf, MAX_BUF_SIZE, 
            "%s -u %s send -m '%s' %s >/dev/null 2>&1",
            signal_prog, username, token, recipients);
    if (snp_ret < 0 || (size_t)snp_ret >= sizeof(char[MAX_BUF_SIZE])) {
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
   
    error: {
        fclose(config_fp); 
        return PAM_AUTH_ERR;
    }
}


/* this function is ripped from pam_unix/support.c, it lets us do IO via PAM */
int converse(pam_handle_t *pamh, int nargs, struct pam_message **message, 
        struct pam_response **response) {
	int ret;
	struct pam_conv *conv;

	ret = pam_get_item(pamh, PAM_CONV, (const void **) &conv); 
	if (ret == PAM_SUCCESS) {
		ret = conv->conv(nargs, (const struct pam_message **) message, 
                response, conv->appdata_ptr);
	}

	return ret;
}


int send_signal_msg_and_wait_for_response(pam_handle_t *pamh, int flags,
        const char *signal_cmd, char response_buf[MAX_BUF_SIZE]) {
    int ret;

    // send the actual signal message
    ret = system(signal_cmd);

    if (ret != EXIT_SUCCESS) {
        return PAM_AUTH_ERR;    
    }

    // these guys will be used by converse()
    struct pam_message msg[1];
    struct pam_message *pmsg[1];
    struct pam_response *resp;

    // setting up conversation call prompting for one-time code
    // this is what will be seen on your ssh prompt
    pmsg[0] = &msg[0];
    msg[0].msg_style = PAM_PROMPT_ECHO_ON;
    msg[0].msg = "1-time code: ";
    resp = NULL;
    if ((ret = converse(pamh, 1 , pmsg, &resp)) != PAM_SUCCESS) {
        // if this function fails, make sure that 
        // ChallengeResponseAuthentication in sshd_config is set to yes
        return ret;
    }

    // retrieving user input
    if(resp) {
        if (resp[0].resp == NULL) {
            free(resp);
            return PAM_AUTH_ERR;
        }
        ret = snprintf(response_buf, sizeof(char[MAX_BUF_SIZE]), "%s", resp[0].resp);
        resp[0].resp = NULL; 		  				  
        if (ret < 0 || (size_t)ret >= MAX_BUF_SIZE){
            return PAM_AUTH_ERR;
        }
    } 
    else {
        return PAM_CONV_ERR;
    }
    return PAM_SUCCESS;
}

// This is the entry point, think of it as main()
/* PAM entry point for authentication verification */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int ret;

    bool nullok = !(flags & PAM_DISALLOW_NULL_AUTHTOK);

    while (argc > 0) {
        const char *arg = *argv;
        if (strcmp(arg, "nullok") == 0) {
            nullok = true;
        }
        else if (strcmp(arg, "nonull") == 0) {
            nullok = false;
        }
        argc--;
        argv++;
    }

    int NULL_FAILURE = nullok ? PAM_SUCCESS : PAM_AUTH_ERR;

    //determine the user
    const char *user = NULL;
    if ((ret = get_user(pamh, &user)) != PAM_SUCCESS) {
        log_message(LOG_ERR, pamh, "failed to get user");
        return ret;
    }

    //get the user's home, uid, and gid
    struct passwd *pw = NULL;
    struct passwd pw_s;
    char passdw_char_buf[MAX_BUF_SIZE] = {0};
    ret = getpwnam_r(user, &pw_s, passdw_char_buf, sizeof(passdw_char_buf), &pw);
    if (ret != 0 || pw == NULL || pw->pw_dir == NULL || pw->pw_dir[0] != '/') {
        log_message(LOG_ERR, pamh, "failed to get uid or gid");
        return PAM_AUTH_ERR;
    }
    const char *home_dir = pw->pw_dir;
    const uid_t uid = pw->pw_uid;
    const gid_t gid = pw->pw_gid;

    // check that user wants 2 factor authentication
    char config_filename_buf[MAX_BUF_SIZE] = {0};
    if (get_2fa_config_filename(home_dir, config_filename_buf) != PAM_SUCCESS) {
        log_message(LOG_ERR, pamh, "failed to get config filename");
        return NULL_FAILURE;
    }

    const char *config_filename = config_filename_buf;
    if (!config_exists_permissions_good(uid, gid, config_filename)) {
        log_message(LOG_ERR, pamh, "config doesnt exist or bad permissions");
        return NULL_FAILURE;
    }

    // at this point we know the user must do 2fa,
    // they either opted in by putting the config file where it should be
    // or the sysadmin requires 2fa
    // (though the user may still have an invalid config file)
    // from here on failures should err on the side of denying access

    if ((ret = drop_privileges(uid, gid)) != PAM_SUCCESS ) {
        log_message(LOG_ERR, pamh, "failed to drop privileges");
        return ret;
    }

    char token_buf[TOKEN_LEN+1] = {0};
    if ((ret = generate_random_token(token_buf)) != PAM_SUCCESS) {
        log_message(LOG_ERR, pamh, "failed to generate random token");
        return ret;
    }
    const char *token = token_buf;

    char signal_cmd_buf[MAX_BUF_SIZE] = {0};
    if ((ret = build_signal_command(config_filename, token, signal_cmd_buf)) 
            != PAM_SUCCESS) {
        log_message(LOG_ERR, pamh, "failed to build signal command");
        return ret;
    }
    const char *signal_cmd = signal_cmd_buf;

    char response_buf[MAX_BUF_SIZE] = {0};
    if (send_signal_msg_and_wait_for_response(pamh, flags, signal_cmd,
                response_buf) != PAM_SUCCESS) {
        log_message(LOG_ERR, pamh, "failed to send signal message or get response");
        return PAM_AUTH_ERR;
    }
    const char *response = response_buf;

    if(strlen(response) != TOKEN_LEN || strncmp(response, token, TOKEN_LEN) != 0) {
        log_message(LOG_ERR, pamh, "incorrect token");
        return PAM_AUTH_ERR;
    }

    return PAM_SUCCESS;
}

/*
 PAM entry point for setting user credentials (that is, to actually
 establish the authenticated user's credentials to the service provider)
*/
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

/* PAM entry point for authentication token (password) changes */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}
