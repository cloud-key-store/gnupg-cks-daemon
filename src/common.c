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

#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "common.h"

static FILE *log_stream = NULL;

void
common_set_log_stream (FILE *log) {
	log_stream = log;
}

FILE *
common_get_log_stream (void) {
	return log_stream;
}

void
common_vlog (
	common_log_t class,
	const char * const format,
	va_list args
) {
	unsigned id;
	id = (unsigned)pthread_self ();

	if (log_stream != NULL) {
		fprintf (log_stream, "%s[%u.%u]: ", PACKAGE, (unsigned)getpid (), id);
		vfprintf (log_stream, format, args);
		fputc ('\n', log_stream);
		fflush (log_stream);
		if (class == LOG_FATAL) {
			exit (1);
		}
	}
}

void
common_log (
	common_log_t class,
	const char * const format,
	...
) {
	if (log_stream != NULL) {
		va_list args;

		va_start (args, format);
		common_vlog (class, format, args);
		va_end (args);
	}
}

/* Get address information, create socket and bind to the port */
int init_socket(const char* hostname, in_port_t port, bool server_side, const char* localaddr)
{
  char str_port[6] = {0};
  struct addrinfo hints;
  struct sockaddr_in sin;
  struct addrinfo *res, *cur;
  int sd;
  int err = 0;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  sprintf(str_port, "%u", port);
  err = getaddrinfo(hostname, str_port, &hints, &res);
  if( err != 0 ) {
    fprintf(stderr, "Socket init, getaddrinfo(): %s\n", gai_strerror(err));
    return -1;
  }

  for( cur = res; cur != NULL; cur = cur->ai_next )
  {
    if( (sd = socket( cur->ai_family, cur->ai_socktype, cur->ai_protocol )) == -1 )
    {
      perror("Socket init, socket():");
      continue;
    }
    if( server_side && (bind(sd, cur->ai_addr, cur->ai_addrlen) == -1) )
    {
      perror("Socket init, bind():");
      close(sd);
      continue;
    }
    if( !server_side ) {
      if (localaddr != NULL) {
        memset(&sin, 0, sizeof(struct sockaddr_in));
        sin.sin_family = AF_INET;
        sin.sin_port = 0;
        sin.sin_addr.s_addr = inet_addr(localaddr);
        printf("binding");
        if ( bind(sd, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1) {
          perror("Local socket binding, bind():");
          continue;
        }
      }
      if ( connect(sd, cur->ai_addr, cur->ai_addrlen) == -1) {
        perror("Socket init, connect():");
        continue;
      }
    }
    break;
  }

  if( cur == NULL ) sd = -1;

  freeaddrinfo(res);
  return sd;
}

int write_all(int sd, const void* buf, size_t count) {
  const char* p = (char*)buf;
  int n;

  do {
    n = write(sd, p, count);
    if( n == -1 ) {
      return -1;
    }
    count -= n;
    p += n;
  } while( count > 0 );
}
