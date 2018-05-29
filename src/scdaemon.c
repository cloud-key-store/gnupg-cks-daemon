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

/**
   @file
   Main command loop for scdaemon. For compatibility with GnuPG's scdaemon,
   all command-line options are silently ignored.

   @todo True daemon mode and multi-server mode are not yet implemented. Only
   one card is currently supported. Client notification of card status change
   is not implemented.
*/

#include "common.h"
#include "command.h"
// #include "dconfig.h"

#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#ifdef HAVE_SYS_UCRED_H
#include <sys/ucred.h>
#endif

#if defined(USE_GNUTLS)
#include <gnutls/gnutls.h>
#endif

typedef int gnupg_fd_t;
#define GNUPG_INVALID_FD (-1)
#define INT2FD(s) (s)
#define FD2INT(h) (h)

typedef enum {
	ACCEPT_THREAD_STOP,
	ACCEPT_THREAD_CLEAN
} accept_command_t;

struct global_s;

typedef struct thread_list_s {
	struct thread_list_s *next;
	int fd;
	pthread_t thread;
	int stopped;
	struct global_s *global;
} *thread_list_t;

typedef struct global_s {
	char *socket_name;

	thread_list_t *threads;
	char *socket_dir;
	int fd_accept_terminate[2];
	uid_t uid_acl;

} global_t;

static int s_parent_pid = -1;

#define ALARM_INTERVAL 10
#define SOCKET_DIR_TEMPLATE ( PACKAGE ".XXXXXX" )

/** Register commands with assuan. */
static
int
register_commands (const assuan_context_t ctx)
{
	static struct {
		const char *name;
		assuan_handler_t handler;
		const char * const help;
	} table[] = {
		{ "SERIALNO", cmd_serialno, NULL },
		{ "LEARN", cmd_learn, NULL },
		{ "GETATTR", cmd_getattr, NULL },
		{ "SETATTR", cmd_setattr, NULL },
		{ "WRITEKEY", cmd_writekey, NULL },
		{ "RESTART", cmd_restart, NULL },
		{ "SETDATA", cmd_setdata, NULL },
		{ "CHECKPIN", cmd_checkpin, NULL },
		{ "GENKEY", cmd_genkey, NULL },
		{ "PKSIGN", cmd_pksign, NULL },
		{ "PKDECRYPT", cmd_pkdecrypt, NULL },
		{ "GETINFO", cmd_getinfo, NULL },
		{ "READKEY", cmd_readkey, NULL },
		{ NULL, NULL, NULL }
	};
	int i, ret;

	for(i=0; table[i].name; i++) {
		if (
			(ret = assuan_register_command (
				ctx,
				table[i].name,
				table[i].handler,
				table[i].help
			))
		) {
			return ret;
		}
	} 

	assuan_set_hello_line (ctx, "Cloud Key Store server(client) for GnuPG ready");
	/*assuan_register_reset_notify(ctx, reset_notify);*/
	/*assuan_register_option_handler(ctx, option_handler);*/
	return 0;
}

/**
   Command handler (single-threaded). If fd == -1, this is a pipe server,
   otherwise fd is UNIX socket fd to which client connected.
*/
static
void
command_handler (global_t *global, const int fd)
{
	assuan_context_t ctx = NULL;
	cmd_data_t data;
	int ret;

	if (fd != -1 && global->uid_acl != (uid_t)-1) {
		uid_t peeruid = -1;
#if HAVE_DECL_LOCAL_PEERCRED
		struct xucred xucred;
		socklen_t len = sizeof(xucred);
		if (getsockopt(fd, SOL_SOCKET, LOCAL_PEERCRED, &xucred, &len) == -1) {
			common_log (LOG_WARNING, "Cannot get socket credentials: %s", strerror (errno));
			goto cleanup;
		}
		if (xucred.cr_version != XUCRED_VERSION) {
			common_log (LOG_WARNING, "Mismatch credentials version actual %d expected %d", xucred.cr_version, XUCRED_VERSION);
			goto cleanup;
		}
		peeruid = xucred.cr_uid;
#elif HAVE_DECL_SO_PEERCRED
		struct ucred ucred;
		socklen_t len = sizeof(ucred);
		if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) == -1) {
			common_log (LOG_WARNING, "Cannot get socket credentials: %s", strerror (errno));
			goto cleanup;
		}
		peeruid = ucred.uid;
#endif
		if (peeruid != global->uid_acl) {
			common_log (LOG_WARNING, "Mismatch credentials actual %d expected %d", peeruid, global->uid_acl);
			goto cleanup;
		}
	}

	memset (&data, 0, sizeof (data));
	data.socket_name = global->socket_name;

	if ((ret = assuan_new(&ctx)) != 0) {
		common_log (LOG_ERROR,"failed to create assuan context %s", gpg_strerror (ret));
		goto cleanup;
	}

	if(fd < 0) {
		assuan_fd_t fds[2] = {INT2FD(0), INT2FD(1)};
		ret = assuan_init_pipe_server (ctx, fds);
	} else {
		ret = assuan_init_socket_server (ctx, INT2FD(fd), ASSUAN_SOCKET_SERVER_ACCEPTED);
	}

	if (ret != 0) {
		common_log (LOG_ERROR,"failed to initialize server: %s", gpg_strerror (ret));
		goto cleanup;
	}

	if(((ret = register_commands(ctx))) != 0) {
		common_log (LOG_ERROR,"failed to register assuan commands: %s", gpg_strerror (ret));
		goto cleanup;
	}

//	if (global->config.verbose) {
		assuan_set_log_stream (ctx, common_get_log_stream());
//	}

	assuan_set_pointer (ctx, &data);

	while (1) {
		common_log (LOG_DEBUG, "accepting connection");

		if ((ret = assuan_accept (ctx)) == -1) {
			break;
		}

		if (ret != 0) {
			common_log (LOG_WARNING,"assuan_accept failed: %s", gpg_strerror(ret));
			break;
		}

		common_log (LOG_DEBUG, "processing connection");

		if ((ret = assuan_process (ctx)) != 0) {
			common_log (LOG_WARNING,"assuan_process failed: %s", gpg_strerror(ret));
		}

		common_log (LOG_DEBUG, "post-processing connection");
	}

cleanup:

	common_log (LOG_DEBUG, "cleanup connection");

	if (ctx != NULL) {
		cmd_free_data (ctx);
		assuan_release (ctx);
		ctx = NULL;
	}
}

static
void
server_socket_close (global_t *global, const int fd) {
	if (fd != -1) {
		assuan_sock_close (fd);
	}
	if (global->socket_name != NULL) {
		unlink (global->socket_name);
		free (global->socket_name);
		global->socket_name = NULL;
	}
	if (global->socket_dir != NULL) {
		rmdir (global->socket_dir);
		free (global->socket_dir);
		global->socket_dir = NULL;
	}
	assuan_sock_deinit();
}

static
void
server_socket_create_name (global_t *global) {

	char *socketdir = getenv("GNUPG_CKS_SOCKETDIR");
	if (socketdir == NULL) {
		socketdir = getenv("TMPDIR");
	}
	if (socketdir == NULL) {
		socketdir = "/tmp";
	}

	if ((global->socket_dir = malloc(strlen(socketdir) + strlen(SOCKET_DIR_TEMPLATE) + 100)) == NULL) {
		common_log (LOG_FATAL, "malloc");
	}
	sprintf(global->socket_dir, "%s/%s", socketdir, SOCKET_DIR_TEMPLATE);

	if (mkdtemp (global->socket_dir) == NULL) {
		common_log (LOG_FATAL, "Cannot mkdtemp");
	}

	if ((global->socket_name = (char *)malloc (strlen (global->socket_dir) + 100)) == NULL) {
		common_log (LOG_FATAL, "Cannot malloc");
	}

	sprintf (global->socket_name, "%s/agent.S", global->socket_dir);

}

static
int
server_socket_create (global_t *global) {
	struct sockaddr_un serv_addr;
	int fd = -1;
	int rc = -1;

	if ((rc = assuan_sock_init()) != 0) {
		common_log (LOG_ERROR,"Cannot init socket %s", gpg_strerror (rc));
		goto cleanup;
	}

	memset (&serv_addr, 0, sizeof (serv_addr));
	serv_addr.sun_family = AF_UNIX;
	assert (strlen (global->socket_name) + 1 < sizeof (serv_addr.sun_path));
	strcpy (serv_addr.sun_path, global->socket_name);

	if ((fd = assuan_sock_new (AF_UNIX, SOCK_STREAM, 0)) == -1) {
		common_log (LOG_ERROR, "Cannot create  socket", global->socket_name);
		goto cleanup;
	}

	if ((rc = assuan_sock_bind (fd, (struct sockaddr*)&serv_addr, sizeof (serv_addr))) == -1) {
		common_log (LOG_ERROR, "Cannot bing to  socket '%s'", global->socket_name);
		goto cleanup;
	}

	if (global->uid_acl != (uid_t)-1) {
		if (chmod(global->socket_name, 0666) == -1) {
			common_log (LOG_ERROR, "Cannot chmod '%s'", global->socket_name);
			goto cleanup;
		}
		if (chmod(global->socket_dir, 0755) == -1) {
			common_log (LOG_ERROR, "Cannot chmod '%s'", global->socket_dir);
			goto cleanup;
		}
	}

	if ((rc = listen (fd, SOMAXCONN)) == -1) {
		common_log (LOG_ERROR, "Cannot listen to socket '%s'", global->socket_name);
		goto cleanup;
	}

	rc = 0;

cleanup:

	if (rc != 0) {
		server_socket_close (global, fd);
		common_log (LOG_FATAL, "Cannot handle socket");
	}

	common_log (LOG_INFO, "Listening to socket '%s'", global->socket_name);

	return fd;
}

static
void *
_server_socket_command_handler (void *arg) {
	thread_list_t entry = (thread_list_t)arg;
	accept_command_t clean = ACCEPT_THREAD_CLEAN;

	command_handler (entry->global, entry->fd);
	entry->stopped = 1;

	if (write (entry->global->fd_accept_terminate[1], &clean, sizeof (clean)) == -1) {
		common_log (LOG_FATAL, "write failed");
	}

	return NULL;
}

static
void *
_server_socket_accept (void *arg) {
	thread_list_t _entry = (thread_list_t)arg;
	global_t *global = _entry->global;
	int fd = _entry->fd;
	thread_list_t thread_list_head = NULL;
	int rc = 0;

	free (_entry);
	_entry = NULL;

	if (pipe (global->fd_accept_terminate) == -1) {
		common_log (LOG_FATAL, "pipe failed");
	}

	while (rc != -1) {
		fd_set fdset;

		FD_ZERO (&fdset);
		FD_SET (global->fd_accept_terminate[0], &fdset);
		FD_SET (fd, &fdset);

		rc = select (FD_SETSIZE, &fdset, NULL, NULL, NULL);

		if (rc != -1 && rc != 0) {
			if (FD_ISSET (global->fd_accept_terminate[0], &fdset)) {
				accept_command_t cmd;

				if (
					(rc = read (
						global->fd_accept_terminate[0],
						&cmd,
						sizeof (cmd))
					) == sizeof (cmd)
				) {
					if (cmd == ACCEPT_THREAD_STOP) {
						common_log (LOG_DEBUG, "Thread command terminate");
						rc = -1;
					}
					else if (cmd == ACCEPT_THREAD_CLEAN) {
						thread_list_t entry = thread_list_head;
						thread_list_t prev = NULL;

						common_log (LOG_DEBUG, "Cleaning up closed thread");
						while (entry != NULL) {
							if (entry->stopped) {
								thread_list_t temp = entry;

								common_log (LOG_DEBUG, "Cleaning up closed thread1");
								pthread_join (entry->thread, NULL);
								close (entry->fd);

								if (prev == NULL) {
									thread_list_head = entry->next;
								}
								else {
									prev->next = entry->next;
								}

								entry = entry->next;

								free (temp);
							}
							else {
								prev = entry;
								entry = entry->next;
							}
						}
					}
				}
			}
			else if (FD_ISSET (fd, &fdset)) {
				struct sockaddr_un addr;
				socklen_t addrlen = sizeof (addr);
				int fd2;

				if ((rc = fd2 = accept (fd, (struct sockaddr *)&addr, &addrlen)) != -1) {
					thread_list_t entry = NULL;

					common_log (LOG_DEBUG, "Accepted new socket connection");

					if ((entry = (thread_list_t)malloc (sizeof (struct thread_list_s))) == NULL) {
						common_log (LOG_FATAL, "malloc failed");
					}
					memset (entry, 0, sizeof (struct thread_list_s));
					entry->next = thread_list_head;
					entry->fd = fd2;
					entry->global = global;
					thread_list_head = entry;

					if (
						pthread_create (
							&entry->thread,
							NULL,
							_server_socket_command_handler,
							entry
						)
					) {
						common_log (LOG_FATAL, "pthread failed");
					}

				}
			}
		}
	}

	common_log (LOG_DEBUG, "Cleaning up threads");
	while (thread_list_head != NULL) {
		thread_list_t entry = thread_list_head;
		thread_list_head = thread_list_head->next;
		common_log (LOG_DEBUG, "Cleaning up thread1");
		close (entry->fd);
		pthread_join (entry->thread, NULL);
		free (entry);
	}

	return NULL;
}

static
void
server_socket_accept (global_t *global, const int fd, pthread_t *thread) {
	thread_list_t entry = malloc (sizeof (struct thread_list_s));
	memset (entry, 0, sizeof (struct thread_list_s));
	entry->fd = fd;
	entry->global = global;
	if (pthread_create (thread, NULL, _server_socket_accept, (void *)entry)) {
		common_log (LOG_FATAL, "pthread failed");
	}
}

static
void
server_socket_accept_terminate (global_t *global, pthread_t thread) {
	accept_command_t stop = ACCEPT_THREAD_STOP;
	if (write (global->fd_accept_terminate[1], &stop, sizeof (stop)) == -1) {
		common_log (LOG_FATAL, "write failed");
	}
	pthread_join (thread, NULL);
	close (global->fd_accept_terminate[0]);
	close (global->fd_accept_terminate[1]);
}

static RETSIGTYPE on_alarm (int signo)
{
	(void)signo;

	if (s_parent_pid != -1 && kill (s_parent_pid, 0) == -1) {
		kill (getpid (), SIGTERM);
	}

	signal (SIGALRM, on_alarm);
	alarm (ALARM_INTERVAL);

#if RETSIGTYPE != void
	return 0
#endif
}

static RETSIGTYPE on_signal (int signo)
{
	(void)signo;

	/*
	 * This is the only way to notify
	 * assuan to return from its main loop...
	 */
	close (0);
	close (1);

#if RETSIGTYPE != void
	return 0
#endif
}

static void usage (const char * const argv0)
{

	printf (
		(
"%s %s\n"
"\n"
"Copyright (c) 2006-2007 Zeljko Vrba <zvrba@globalnet.hr>\n"
"Copyright (c) 2006-2017 Alon Bar-Lev <alon.barlev@gmail.com>\n"
"This program comes with ABSOLUTELY NO WARRANTY.\n"
"This is free software, and you are welcome to redistribute it\n"
"under certain conditions. See the file COPYING for details.\n"
"\n"
"Syntax: %s [options]\n"
"Cloud Keystore daemon for GnuPG\n"
"\n"
"Options:\n"
" \n"
"     --server              run in server mode (foreground)\n"
"     --multi-server        run in multi server mode (foreground)\n"
"     --daemon              run in daemon mode (background)\n"
" -v, --verbose             verbose\n"
" -q, --quiet               be somewhat more quiet\n"
" -s, --sh                  sh-style command output\n"
" -c, --csh                 csh-style command output\n"
"     --options             read options from file\n"
"     --no-detach           do not detach from the console\n"
"     --homedir             specify home directory\n"
"     --uid-acl             accept only this uid, implies world read/write socket\n"
"     --log-file            use a log file for the server\n"
"     --help                print this information\n"
		),
		PACKAGE,
		PACKAGE_VERSION,
		argv0
	);
}

static char *get_home_dir (void) {

	const char *HOME_ENV = getenv ("HOME");

	char *home_dir = NULL;

	if (home_dir == NULL && getenv ("GNUPGHOME") != NULL) {
		home_dir=strdup (getenv ("GNUPGHOME"));
	}

	return home_dir;
}

int main (int argc, char *argv[])
{
	enum {
		OPT_SERVER,
		OPT_MUTLI_SERVER,
		OPT_DAEMON,
		OPT_VERBOSE,
		OPT_QUIET,
		OPT_SH,
		OPT_CSH,
		OPT_OPTIONS,
		OPT_NO_DETACH,
		OPT_HOMEDIR,
		OPT_UID_ACL,
		OPT_LOG_FILE,
		OPT_VERSION,
		OPT_HELP
	};

	static struct option long_options[] = {
		{ "server", no_argument, NULL, OPT_SERVER },
		{ "multi-server", no_argument, NULL, OPT_MUTLI_SERVER },
		{ "daemon", no_argument, NULL, OPT_DAEMON },
		{ "verbose", no_argument, NULL, OPT_VERBOSE },
		{ "quiet", no_argument, NULL, OPT_QUIET },
		{ "sh", no_argument, NULL, OPT_SH },
		{ "csh", no_argument, NULL, OPT_CSH },
		{ "options", required_argument, NULL, OPT_OPTIONS },
		{ "no-detach", no_argument, NULL, OPT_NO_DETACH },
		{ "homedir", required_argument, NULL, OPT_HOMEDIR },
		{ "uid-acl", required_argument, NULL, OPT_UID_ACL },
		{ "log-file", required_argument, NULL, OPT_LOG_FILE },
		{ "version", no_argument, NULL, OPT_VERSION },
		{ "help", no_argument, NULL, OPT_HELP },
		{ NULL, 0, NULL, 0 }
	};
	int opt;
	enum {
		RUN_MODE_NONE,
		RUN_MODE_SERVER,
		RUN_MODE_MULTI_SERVER,
		RUN_MODE_DAEMON
	} run_mode = RUN_MODE_NONE;
	int env_is_csh = 0;
	int log_verbose = 0;
	int log_quiet = 0;
	int no_detach = 0;
	char *config_file = NULL;
	char *log_file = NULL;
	char *home_dir = NULL;
	int have_at_least_one_provider=0;
	FILE *fp_log = NULL;
	int i;

	global_t global;

	const char * CONFIG_SUFFIX = ".conf";
	char *default_config_file = NULL;

	/* unused intentionally */
	(void)log_quiet;

	memset(&global, 0, sizeof(global));

	s_parent_pid = getpid ();
	global.fd_accept_terminate[0] = -1;
	global.fd_accept_terminate[1] = -1;
	global.uid_acl = (uid_t)-1;

	if ((default_config_file = (char *)malloc (strlen (PACKAGE)+strlen (CONFIG_SUFFIX)+1)) == NULL) {
		common_log (LOG_FATAL, "malloc failed");
	}
	sprintf (default_config_file, "%s%s", PACKAGE, CONFIG_SUFFIX);

	common_set_log_stream (stderr);

	while ((opt = getopt_long (argc, argv, "vqsc", long_options, NULL)) != -1) {
		switch (opt) {
			case OPT_SERVER:
				run_mode = RUN_MODE_SERVER;
			break;
			case OPT_MUTLI_SERVER:
				run_mode = RUN_MODE_MULTI_SERVER;
			break;
			case OPT_DAEMON:
				run_mode = RUN_MODE_DAEMON;
			break;
			case OPT_VERBOSE:
			case 'v':
				log_verbose = 1;
			break;
			case OPT_QUIET:
			case 'q':
				log_quiet = 1;
			break;
			case OPT_SH:
			case 's':
			break;
			case OPT_CSH:
			case 'c':
				env_is_csh = 1;
			break;
			case OPT_OPTIONS:
				config_file = strdup (optarg);
			break;
			case OPT_NO_DETACH:
				no_detach = 1;
			break;
			case OPT_HOMEDIR:
				home_dir = strdup (optarg);
			break;
			case OPT_UID_ACL:
				global.uid_acl = atoi(optarg);
			break;
			case OPT_LOG_FILE:
				log_file = optarg;
			break;
			case OPT_VERSION:
				printf (
					"%s %s\n"
					"\n"
					"Copyright (c) 2006-2007 Zeljko Vrba <zvrba@globalnet.hr>\n"
					"Copyright (c) 2006-2017 Alon Bar-Lev <alon.barlev@gmail.com>\n"
					"\n"
					"This is free software; see the source for copying conditions.\n"
					"There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n",
					PACKAGE,
					PACKAGE_VERSION
				);
				exit (0);
			break;
			case OPT_HELP:
				usage(argv[0]);
				exit(0);
			break;
			default:
				fprintf(stderr, "Invalid usage\n");
				exit(1);
			break;
		}
	}

	if (run_mode == RUN_MODE_NONE) {
		common_log (LOG_FATAL, "please use the option `--daemon' to run the program in the background");
	}

	if (home_dir == NULL) {
		home_dir = get_home_dir ();
	}

	if (config_file == NULL && home_dir != NULL) {
		if ((config_file = (char *)malloc (strlen (home_dir) + strlen (default_config_file)+2)) == NULL) {
			common_log (LOG_FATAL, "malloc failed");
		}
		sprintf (config_file, "%s%c%s", home_dir, CONFIG_PATH_SEPARATOR, default_config_file);
	}

	if (log_verbose) {
	}

	signal (SIGPIPE, SIG_IGN);
	{
		struct sigaction action;
		memset(&action, 0, sizeof(action));
		action.sa_handler = on_signal;
		sigaction(SIGINT, &action, NULL);
		sigaction(SIGTERM, &action, NULL);
		sigaction(SIGABRT, &action, NULL);
		sigaction(SIGHUP, &action, NULL);
	}

	if (log_file == NULL) {
	}

	if (log_file != NULL) {
		if (strcmp (log_file, "stderr") != 0) {
			if ((fp_log = fopen (log_file, "a")) != NULL) {
				fchmod(fileno(fp_log), 0600);
				common_set_log_stream (fp_log);
			}
		}
	}

	if (!gcry_check_version (GCRYPT_VERSION)) {
		common_log (LOG_FATAL, "Cannot initialize libcrypt");
	}
	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

	if (run_mode == RUN_MODE_DAEMON || run_mode == RUN_MODE_MULTI_SERVER) {
		server_socket_create_name (&global);
	}

	/*
	 * fork before doing the job
	 */
	if (run_mode == RUN_MODE_DAEMON) {
		pid_t pid;

		pid = fork ();

		if (pid == -1) {
			common_log (LOG_FATAL, "fork failed");
		}

		if (pid != 0) {
			static const char *key = "SCDAEMON_INFO";
			char env[1024];
			snprintf (env, sizeof (env), "%s:%lu:1", global.socket_name, (unsigned long)pid);

			if (optind < argc) {
				setenv(key, env, 1);
				execvp (argv[optind], &(argv[optind]));
				kill (pid, SIGTERM);
				exit (1);
			}
			else {
				if (env_is_csh) {
					*strchr (env, '=') = ' ';
					printf ("setenv %s %s\n", key, env);
				}
				else {
					printf ("%s=%s; export %s\n", key, env, key);
				}
				exit (0);
			}
		}

		if (!no_detach) {
			int i;

			for (i=0;i<3;i++) {
				if (fileno (common_get_log_stream ()) != i) {
					close (i);
				}
			}

			if (setsid () == -1) {
				common_log (LOG_FATAL, "setsid failed");
			}
		}

		if (chdir ("/") == -1) {
			common_log (LOG_FATAL, "chdir failed");
		}

		if (optind < argc) {
			struct sigaction sa;

			memset (&sa, 0, sizeof (sa));
			sigemptyset (&sa.sa_mask);
#if defined(SA_INTERRUPT)
			sa.sa_flags |= SA_INTERRUPT;
#endif
			sa.sa_handler = on_alarm;
			sigaction (SIGALRM, &sa, NULL);
			alarm (10);
		}
	}

	assuan_set_assuan_log_prefix (PACKAGE);
	assuan_set_assuan_log_stream (common_get_log_stream ());

#if defined(USE_GNUTLS)
	if (gnutls_global_init () != GNUTLS_E_SUCCESS) {
		common_log (LOG_FATAL, "Cannot initialize gnutls");
	}
#endif

{
	pthread_t accept_thread = 0;
	int accept_socket = -1;

	if (run_mode == RUN_MODE_DAEMON || run_mode == RUN_MODE_MULTI_SERVER) {
		accept_socket = server_socket_create (&global);

		server_socket_accept (&global, accept_socket, &accept_thread);
	}

	if (run_mode == RUN_MODE_DAEMON) {
		/*
		 * Emulate assuan behavior
		 */
		int fds[2];
		char c;
		if (pipe (fds)==-1) {
			common_log (LOG_FATAL, "Could not create pipe");
		}
		close (0);
		dup2 (fds[0], 0);
		close (fds[0]);
		while (read (0, &c, 1) == -1 && errno == EINTR);
		close (fds[1]);
	}
	else {
		command_handler (&global, -1);
	}

	common_log (LOG_DEBUG, "Terminating");

	if (run_mode == RUN_MODE_DAEMON || run_mode == RUN_MODE_MULTI_SERVER) {
		server_socket_accept_terminate (&global, accept_thread);
		server_socket_close (&global, accept_socket);
	}
}

#if defined(USE_GNUTLS)
	gnutls_global_deinit ();
#endif

	if (config_file != NULL) {
		free (config_file);
		config_file = NULL;
	}

	if (default_config_file != NULL) {
		free (default_config_file);
		default_config_file = NULL;
	}

	if (home_dir != NULL) {
		free (home_dir);
		home_dir = NULL;
	}

	if (fp_log != NULL) {
		fclose (fp_log);
		fp_log = NULL;
	}

	return 0;
}

