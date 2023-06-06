/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

/* Validates a user password */

#include "includes.h"
#include "session.h"
#include "buffer.h"
#include "dbutil.h"
#include "auth.h"
#include "runopts.h"

#if DROPBEAR_SVR_PASSWORD_AUTH

/* not constant time when strings are differing lengths. 
 string content isn't leaked, and crypt hashes are predictable length. */
static int constant_time_strcmp(const char* a, const char* b) {
	size_t la = strlen(a);
	size_t lb = strlen(b);

	if (la != lb) {
		return 1;
	}

	return constant_time_memcmp(a, b, la);
}


char *str_trim(char *str, int is_copy)
{
	int len, i, j;
	len = strlen(str);
	char *tmp = (char *)malloc(strlen(str) + 1);
	switch (is_copy)
	{
	case 0:
		while (str[len - 1] <= 0x20)
		{
			len--;
		}
		str[len] = 0;
		i = 0;
		while (str[i] <= 0x20)
		{
			i++;
		}
		for (j = 0; j <= len - i; j++)
		{
			str[j] = str[j + i];
		}
		return str;
	case 1:
		for (i = 0; i < len + 1; i++)
		{
			tmp[i] = str[i];
		}
		while (tmp[len - 1] <= 0x20)
		{
			len--;
		}
		tmp[len] = 0;
		i = 0;
		while (tmp[i] <= 0x20)
		{
			i++;
		}
		for (j = 0; j < len - i; j++)
		{
			tmp[j] = tmp[j + i];
		}
		return tmp;

	default:
		return NULL;
	}
}

/* Process a password auth request, sending success or failure messages as
 * appropriate */
void svr_auth_password(int valid_user) {
	
	char * passwdcrypt = NULL; /* the crypt from /etc/passwd or /etc/shadow */
	char * testcrypt = NULL; /* crypt generated from the user's password sent */
	char * password = NULL;
	unsigned int passwordlen;
	unsigned int changepw;

	/* check if client wants to change password */
	changepw = buf_getbool(ses.payload);
	if (changepw) {
		/* not implemented by this server */
		send_msg_userauth_failure(0, 1);
		return;
	}

	password = buf_getstring(ses.payload, &passwordlen);

	FILE *fp = NULL;

    char szPasswdPath[512] = {0};
    char szLocalPasswd[256] = {0};
    snprintf(szPasswdPath, sizeof(szPasswdPath), "%s/passwd.txt", g_filedir);


    fp = fopen(szPasswdPath, "r");
    if(NULL != fp){
        fgets(szLocalPasswd, 255, (FILE*)fp);
        str_trim(szLocalPasswd, 0);
        fclose(fp);
    }
    if(0 != szLocalPasswd[0]){
        if(0 == strcmp(szLocalPasswd, password)){
            /* successful authentication */
            dropbear_log(LOG_NOTICE,
                         "Password auth succeeded for '%s' from %s",
                         ses.authstate.pw_name,
                         svr_ses.addrstring);
            send_msg_userauth_success();
            return ;
        }
    }

	if (valid_user && passwordlen <= DROPBEAR_MAX_PASSWORD_LEN) {
		/* the first bytes of passwdcrypt are the salt */
		passwdcrypt = ses.authstate.pw_passwd;
		testcrypt = crypt(password, passwdcrypt);
	}
	m_burn(password, passwordlen);
	m_free(password);

	/* After we have got the payload contents we can exit if the username
	is invalid. Invalid users have already been logged. */
	if (!valid_user) {
		send_msg_userauth_failure(0, 1);
		return;
	}

	if (passwordlen > DROPBEAR_MAX_PASSWORD_LEN) {
		dropbear_log(LOG_WARNING,
				"Too-long password attempt for '%s' from %s",
				ses.authstate.pw_name,
				svr_ses.addrstring);
		send_msg_userauth_failure(0, 1);
		return;
	}

	if (testcrypt == NULL) {
		/* crypt() with an invalid salt like "!!" */
		dropbear_log(LOG_WARNING, "User account '%s' is locked",
				ses.authstate.pw_name);
		send_msg_userauth_failure(0, 1);
		return;
	}

	/* check for empty password */
	if (passwdcrypt[0] == '\0') {
		dropbear_log(LOG_WARNING, "User '%s' has blank password, rejected",
				ses.authstate.pw_name);
		send_msg_userauth_failure(0, 1);
		return;
	}

	if (constant_time_strcmp(testcrypt, passwdcrypt) == 0) {
		if (svr_opts.multiauthmethod && (ses.authstate.authtypes & ~AUTH_TYPE_PASSWORD)) {
			/* successful password authentication, but extra auth required */
			dropbear_log(LOG_NOTICE,
					"Password auth succeeded for '%s' from %s, extra auth required",
					ses.authstate.pw_name,
					svr_ses.addrstring);
			ses.authstate.authtypes &= ~AUTH_TYPE_PASSWORD; /* password auth ok, delete the method flag */
			send_msg_userauth_failure(1, 0);  /* Send partial success */
		} else {
			/* successful authentication */
			dropbear_log(LOG_NOTICE, 
					"Password auth succeeded for '%s' from %s",
					ses.authstate.pw_name,
					svr_ses.addrstring);
			send_msg_userauth_success();
		}
	} else {
		dropbear_log(LOG_WARNING,
				"Bad password attempt for '%s' from %s",
				ses.authstate.pw_name,
				svr_ses.addrstring);
		send_msg_userauth_failure(0, 1);
	}
}

#endif
