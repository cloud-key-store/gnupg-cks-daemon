/*
 * Copyright (c) 2006-2007 Zeljko Vrba <zvrba@globalnet.hr>
 * Copyright (c) 2006-2017 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     o Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     o Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     o Neither the name of the <ORGANIZATION> nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* Copyright (c) 2018 Aalto University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "common.h"
#include "command.h"
#include "sexp.h"
#include "utils.h"

#include <stdio.h>
#include <time.h>
#include <sys/time.h>

#define _M2S(x) #x
#define M2S(x) _M2S(x)

#define SERIALNO_STR "D27600012401CDEF0123456789ABCDEF"
#define MAXLEN_KEYDATA 4096

static char setdata_data[MAXLEN_KEYDATA];
static int setdata_len;

static unsigned char asn256[19] = /* Object ID is  2.16.840.1.101.3.4.2.1 */
  { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20 };

#define spacep(p)   (*(p) == ' ' || *(p) == '\t')

static char* skip_options(const char *line)
{
  while( spacep( line ) )
    line++;
  while( *line == '-' && line[1] == '-' )
  {
    while( *line && !spacep( line ) )
      line++;
    while( spacep( line ) )
      line++;
  }
  return (char*) line;
}

void cmd_free_data (assuan_context_t ctx) {
    cmd_data_t *data = (cmd_data_t *)assuan_get_pointer (ctx);
    if (data->data != NULL) {
        free (data->data);
        data->data = NULL;
        data->size = 0;
    }
}

gpg_error_t cmd_getinfo (assuan_context_t ctx, char *line)
{
    char buffer[200];
    const char* keyword;
    keyword = line;

    if (!strncmp (keyword, "GETINFO version", 15)) {
        assuan_write_status (ctx, "GETINFO", VERSION);
        return gpg_error (GPG_ERR_NO_ERROR);
    }

    return gpg_error (GPG_ERR_NO_ERROR);
}

gpg_error_t cmd_null (assuan_context_t ctx, char *line)
{
    (void)ctx;
    (void)line;

    return gpg_error (GPG_ERR_NO_ERROR);
}

gpg_error_t cmd_checkpin (assuan_context_t ctx, char *line)
{
    (void)ctx;
    (void)line;

    return gpg_error (GPG_ERR_NO_ERROR);
}

gpg_error_t cmd_serialno (assuan_context_t ctx, char *line)
{
    (void)line;

    assuan_write_status (ctx, "SERIALNO", SERIALNO_STR);
    return gpg_error (GPG_ERR_NO_ERROR);
}

gpg_error_t cmd_learn (assuan_context_t ctx, char *line)
{
    (void)line;

    assuan_write_status (ctx, "SERIALNO", SERIALNO_STR);
    return gpg_error (GPG_ERR_NO_ERROR);
}

#define HOSTNAME_SIZE 200
#define PUBKEY_ALGO_RSA 1
#define PUBKEY_ALGO_ECDH 18
#define PUBKEY_ALGO_ECDSA 19

int cks_transact (char* buf, int len, int maxlen);
int construct_operation_sexp (const char* op_str, char* buffer, int len);
gpg_error_t cmd_getattr (assuan_context_t ctx, char *line)
{
    char buffer[200];
    const char* keyword;
    const char* str_a;
    struct sexp *resp, *sexp_a;
    int ret, nbytes;
    keyword = line;
    int keyno = 1;


    if (!strncmp (keyword, "SERIALNO", 8)) {
        return cmd_serialno (ctx, line);
    } else if (!strncmp (keyword, "KEY-ATTR", 8)) {
        nbytes = construct_operation_sexp("keyattr", buffer, 200);
        ret = cks_transact(buffer, nbytes, 200);
        if( ret == -1 )
            return gpg_error (GPG_ERR_GENERAL);

        ret = sexp_parse( &resp, (const char*)buffer, ret );

        while(true) {
          snprintf( buffer, sizeof buffer, "key%d_algo", keyno );
          if( (sexp_a = sexp_get( resp, buffer )) == NULL ) {
              sexp_free(resp);
              if( keyno > 1 )
                return gpg_error( GPG_ERR_NO_ERROR );
              else
                return gpg_error (GPG_ERR_GENERAL);
          }

          str_a = (const char*)sexp_get_str( sexp_a, &nbytes );
          snprintf (buffer, sizeof buffer, "%d %s", keyno, str_a);
          assuan_write_status (ctx, keyword, buffer);

          snprintf( buffer, sizeof buffer, "key%d_fpr", keyno );
          if( (sexp_a = sexp_get( resp, buffer )) == NULL ) {
              sexp_free(resp);
              return gpg_error (GPG_ERR_GENERAL);
          }

          str_a = (const char*)sexp_get_str( sexp_a, &nbytes );

          memset( buffer, sizeof buffer, 0 );
          ret = snprintf( buffer, sizeof buffer, "%d ", keyno );
          bytes2hex(str_a, nbytes, &(buffer[ret]));
          assuan_write_status (ctx, "KEY-FPR", buffer);

          keyno++;
        }

        sexp_free(resp);
        assuan_write_status (ctx, "DISP-NAME", "Card Owner");

	    return gpg_error (GPG_ERR_NO_ERROR);
    } else if (!strncmp (keyword, "EXTCAP", 6)) {
        snprintf (buffer, sizeof buffer, "ki=1 aac=1");
        assuan_write_status (ctx, keyword, buffer);
	    return gpg_error (GPG_ERR_NO_ERROR);
    } else if (!strncmp (keyword, "CHV-STATUS", 6)) {
        snprintf (buffer, sizeof buffer, "%%01");
        assuan_write_status (ctx, keyword, buffer);
	    return gpg_error (GPG_ERR_NO_ERROR);
    }

    return gpg_error (GPG_ERR_NO_ERROR);
}

gpg_error_t cmd_setattr (assuan_context_t ctx, char *line)
{
    char buffer[200];
    const char* keyword;
    keyword = line;

    if (!strncmp (keyword, "CHV-STATUS", 10)) {
        return gpg_error (GPG_ERR_NO_ERROR);
    }

    return gpg_error (GPG_ERR_NO_ERROR);
}

void fill_sexp(struct sexp **bundle, const char* operation_str, int with_data);
gpg_error_t cmd_writekey (assuan_context_t ctx, char *line)
{
	  int rc;
    unsigned char *keydata;
    struct sexp* keydata_sexp;
    struct sexp* bundle;
    size_t keydatalen;
    char buffer[2000] = {0};
    int ret, nbytes;
    (void)line;

    assuan_begin_confidential (ctx);
    rc = assuan_inquire (ctx, "KEYDATA", &keydata, &keydatalen, MAXLEN_KEYDATA);
    assuan_end_confidential (ctx);

    fill_sexp( &bundle, "writekey", 0 );
    sexp_new_string_len( &keydata_sexp, keydata, keydatalen );
    sexp_add( bundle, keydata_sexp );
    nbytes = sexp_serialize( bundle, buffer, 2000 );
    sexp_free( bundle );

    ret = cks_transact(buffer, nbytes, 2000);
    if( ret == -1 )
        return gpg_error (GPG_ERR_GENERAL);

    return gpg_error (GPG_ERR_NO_ERROR);
}

gpg_error_t cmd_genkey (assuan_context_t ctx, char *line)
{
    char buffer[1000];
    const char* keyword;
    const char* str_a = NULL;
    struct sexp *resp, *sexp_a, *bundle, *keyid;
    keyword = line;
    int ret, nbytes;

    fill_sexp( &bundle, "genkey", 0 );
    line = skip_options( line );
    sexp_new_pair( &keyid, "keyid", line );
    sexp_add( bundle, keyid );
    nbytes = sexp_serialize( bundle, buffer, 400 );
    sexp_free( bundle );

    assuan_write_status (ctx, "PROGRESS", NULL);
    ret = cks_transact(buffer, nbytes, 1000);
    if( ret == -1 )
        return gpg_error (GPG_ERR_GENERAL);

    ret = sexp_parse( &resp, (const char*)buffer, ret );

    if( (sexp_a = sexp_get( resp, "q" )) != NULL ) {

        str_a = (const char*)sexp_get_str( sexp_a, NULL );
        snprintf (buffer, sizeof buffer, "q %s", str_a);

    } else if ( (sexp_a = sexp_get( resp, "e" )) != NULL ) {

        str_a = (const char*)sexp_get_str( sexp_a, NULL );
        snprintf (buffer, sizeof buffer, "e %s", str_a);

    }

    sexp_free(resp);

    if( str_a ) {
        assuan_write_status (ctx, "KEY-DATA", buffer);
        return gpg_error (GPG_ERR_NO_ERROR);
    } else
        return gpg_error (GPG_ERR_GENERAL);

}

gpg_error_t cmd_readkey (assuan_context_t ctx, char *line)
{
    char buffer[1000];
    const char* keyword;
    const char* str_a;
    struct sexp *resp, *sexp_a, *bundle, *keyid;
    keyword = line;
    int ret, nbytes;

    fill_sexp( &bundle, "readkey", 0 );
    line = skip_options( line );
    sexp_new_pair( &keyid, "keyid", line );
    sexp_add( bundle, keyid );
    nbytes = sexp_serialize( bundle, buffer, 1000 );
    sexp_free( bundle );

    ret = cks_transact(buffer, nbytes, 1000);
    if( ret == -1 )
        return gpg_error (GPG_ERR_GENERAL);

    assuan_send_data (ctx, buffer, ret);

    return gpg_error (GPG_ERR_NO_ERROR);
}

gpg_error_t cmd_restart (assuan_context_t ctx, char *line)
{
    (void)ctx;
    (void)line;

    return gpg_error (GPG_ERR_NO_ERROR);
}

void fill_sexp(struct sexp **bundle, const char* operation_str, int with_data)
{
    struct sexp *username_symbol, *username, *password_symbol, *password;
    struct sexp *op_symbol, *operation, *op_list;
    struct sexp *hash_symbol, *hash_data, *hash_list;
    struct sexp *username_list, *password_list;

    sexp_new_string( &op_symbol, "operation" );
    sexp_new_string( &operation, operation_str );
    sexp_new_list( &op_list );
    sexp_add( op_symbol, operation );
    sexp_add( op_list, op_symbol );

    sexp_new_string( &username_symbol, "username" );
    sexp_new_string( &username, "test_user" );
    sexp_new_list( &username_list );
    sexp_add( username_symbol, username );
    sexp_add( username_list, username_symbol );

    sexp_new_string( &password_symbol, "password" );
    sexp_new_string( &password, "test_password" );
    sexp_new_list( &password_list );
    sexp_add( password_symbol, password );
    sexp_add( password_list, password_symbol );

    if( with_data ) {
      sexp_new_string( &hash_symbol, "data" );
      sexp_new_string_len( &hash_data, setdata_data, setdata_len );
      sexp_new_list( &hash_list );
      sexp_add( hash_symbol, hash_data );
      sexp_add( hash_list, hash_symbol );
      sexp_add( password_list, hash_list );
    }

    sexp_new_list( bundle );
    sexp_add( op_list, username_list );
    sexp_add( username_list, password_list );
    sexp_add( *bundle, op_list );
}

gpg_error_t cmd_pksign (assuan_context_t ctx, char *line)
{
    char buffer[400];
    struct sexp *bundle, *keyid;
    const char* keyword;
    int ret, nbytes;
    keyword = line;

    fill_sexp( &bundle, "pksign", 1 );
    line = skip_options( line );
    sexp_new_pair( &keyid, "signing_key", line );
    sexp_add( bundle, keyid );
    nbytes = sexp_serialize( bundle, buffer, 400 );
    sexp_free( bundle );

    ret = cks_transact(buffer, nbytes, 400);
    if( ret == -1 )
        return gpg_error (GPG_ERR_GENERAL);

    assuan_send_data( ctx, buffer, ret );
    return gpg_error (GPG_ERR_NO_ERROR);
}

gpg_error_t cmd_pkdecrypt (assuan_context_t ctx, char *line)
{
    char buffer[900];
    const char* keyword;
    int ret, nbytes, n;
    keyword = line;
    struct sexp *bundle;

    fill_sexp( &bundle, "pkdecrypt", 1 );
    nbytes = sexp_serialize( bundle, buffer, 900 );
    sexp_free( bundle );

    ret = cks_transact(buffer, nbytes, 900);
    if( ret == -1 )
        return gpg_error (GPG_ERR_GENERAL);

    // The keystore returns the cryptogram
    // 0 2 RND 0 A DEK
    // Skip random bytes
    for( n = 1; n < 900 && buffer[n]; n++ );
    n++;
    assuan_send_data( ctx, buffer+n, ret-n );
    return gpg_error (GPG_ERR_NO_ERROR);
}

gpg_error_t cmd_setdata (assuan_context_t ctx, char *line)
{
    (void)ctx;
    int len;

    setdata_len = hex2bytes(line, strlen(line), setdata_data);

    return gpg_error (GPG_ERR_NO_ERROR);
}

int cks_transact (char* buf, int len, int maxlen) {
    in_port_t port = 7000;
    int client_sd = -1;
    char hostname[HOSTNAME_SIZE] = "localhost";

    client_sd = init_socket(hostname, port, false, NULL);
    if( client_sd == -1 )
        return -1;

    if( write_all( client_sd, buf, len ) < 0 )
        return -1;

    len = read(client_sd, buf, maxlen);
    close(client_sd);
    return len;
}

int construct_operation_sexp (const char* op_str, char* buffer, int len) {
    int ret;
    struct sexp *username_symbol, *username, *username_list;
    struct sexp *op_symbol, *operation, *op_list;
    struct sexp *bundle;

    fill_sexp( &bundle, op_str, 0 );

    ret = sexp_serialize( bundle, buffer, len );
    sexp_free( bundle );

    return ret;
}
