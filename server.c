/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 Corey Hinshaw
 * Released under the terms of the MIT license.
 * See LICENSE file for details.
 */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 500
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <magic.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uriparser/Uri.h>
#include "lib/common.h"
#include "lib/protocol.h"
#include "lib/uriutil.h"
#include "lib/xdgmime/xdgmime.h"
#include "version.h"

#define PROGNAME "agena"

#define ESSL_WRITE -1000


typedef struct Documents {
	char *path;
	char *mime_type;
	FILE *fp;
	struct stat *statbuf;
} Document;

typedef struct Clients {
	char request[REQUEST_SIZE + 1];
	char ip[INET6_ADDRSTRLEN];
} Client;


static char *root_path = ".";
static char *cert_path = "cert.pem";
static char *key_path = "key.pem";
static unsigned int port = GEMINI_PORT;
static char *hostname = NULL;
static char *index_file = "index.gemini";


static int create_socket(int port) {
	int s;
	int reuseaddr = 1;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof reuseaddr);

	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Unable to bind");
		exit(EXIT_FAILURE);
	}

	if (listen(s, 1) < 0) {
		perror("Unable to listen");
		exit(EXIT_FAILURE);
	}

	return s;
}

static void init_openssl() {
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

static void cleanup_openssl() {
	EVP_cleanup();
}

static SSL_CTX *create_context() {
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

static void configure_context(SSL_CTX *ctx) {
	SSL_CTX_set_ecdh_auto(ctx, 1);

	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

static void read_request(BIO *io, char *req) {
	int r;
	SSL *ssl = NULL;
	BIO_get_ssl(io, ssl);

	r = BIO_gets(io, req, REQUEST_SIZE-1);
	if (SSL_get_error(ssl, r) != SSL_ERROR_NONE) {
		perror("SSL read error");
		req = NULL;
		return;
	}
	req[strcspn(req, LINE_TERM)] = 0;
}

static bool is_gemini_file(char *path) {
	size_t lenpath = strlen(path);
	size_t lenext = strlen(GEMINI_EXTENSION);
	if (lenext >  lenpath) return false;

	return strncmp(path + lenpath - lenext, GEMINI_EXTENSION, lenext) == 0;
}

static void set_mime_type(Document *file) {
	const char *mime_type;
	const char *mime_encoding;
	magic_t cookie;
	size_t mimelen;

	if (is_gemini_file(file->path)) {
		mime_type = GEMINI_MIME;
	} else {
		mime_type = xdg_mime_get_mime_type_for_file(file->path, file->statbuf);
	}

	if (xdg_mime_media_type_equal(mime_type, "text/")) {
		cookie = magic_open(MAGIC_MIME_ENCODING);
		magic_load(cookie, NULL);
		mime_encoding = magic_file(cookie, file->path);
		if (strcasecmp(mime_encoding, "us-ascii") == 0) {
			mime_encoding = "utf-8";
		}

		mimelen = strlen(mime_type) + strlen(mime_encoding) + 11;
		file->mime_type = malloc(mimelen);
		strcpy(file->mime_type, mime_type);
		strcat(file->mime_type, "; charset=");
		strcat(file->mime_type, mime_encoding);

		magic_close(cookie);
	} else {
		file->mime_type = strdup(mime_type);
	}
}

static void open_file(Document *file, char *req_path) {
	bool file_in_root;
	char *resolved_path;
	size_t pathlen = strlen(root_path) + strlen(req_path) + 1;
	char *full_path = malloc(pathlen);

	strcpy(full_path, root_path);
	strcat(full_path, req_path);

	resolved_path = realpath(full_path, NULL);
	if (resolved_path && stat(resolved_path, file->statbuf) >= 0) {
		if (S_ISDIR(file->statbuf->st_mode)) {
			pathlen = strlen(resolved_path) + strlen(PATH_SEPARATOR) + strlen(index_file) + 1;
			resolved_path = realloc(resolved_path, pathlen);
			strcat(resolved_path, PATH_SEPARATOR);
			strcat(resolved_path, index_file);
			if (stat(resolved_path, file->statbuf) >= 0 && S_ISREG(file->statbuf->st_mode)) {
				file->path = strdup(resolved_path);
			}
		} else {
			file->path = strdup(resolved_path);
		}
	}
	file_in_root = file->path && strncmp(root_path, file->path, strlen(root_path)) == 0;

	if (file_in_root) {
		file->fp = fopen(file->path, "rb");
		set_mime_type(file);
	}

	free(resolved_path);
	free(full_path);
}

static bool valid_hostname(UriTextRangeA *hostText) {
	const char *delim = ",";
	char *token;

	if (!hostname) return true;

	token = strtok(hostname, delim);
	while (token != NULL) {
		if (uricmp(hostText, token) == 0) {
			return true;
		}
		token = strtok(NULL, delim);
	}
	return false;
}

static void build_header(char *header, const char *status, const char *meta) {
	if (meta != NULL) {
		snprintf(header, HEADER_SIZE, "%s %s" LINE_TERM, status, meta);
	} else {
		snprintf(header, HEADER_SIZE, "%s" LINE_TERM, status);
	}
}

static void prepare_response(char *header, Document *file, Client client) {
	UriUriA uri;
	const char *uriErrorPos;
	header[0] = '\0';

	if (uriParseSingleUriA(&uri, client.request, &uriErrorPos) != URI_SUCCESS
			|| uriNormalizeSyntaxA(&uri) != URI_SUCCESS) {
		printf("[%s] Error parsing request\n", client.ip);
		build_header(header, STATUS_BAD_REQUEST, "Could not parse request URL");
		return;
	}

	if (&uri.hostText == NULL || urilen(&uri.hostText) == 0) {
		build_header(header, STATUS_BAD_REQUEST, "No host in request");
		goto cleanup;
	} else if (!valid_hostname(&uri.hostText)) {
		build_header(header, STATUS_PROXY_REFUSED, "Will not proxy for requested hostname");
		goto cleanup;
	}
	if (&uri.scheme != NULL && uricmp(&uri.scheme, GEMINI_SCHEME) != 0) {
		build_header(header, STATUS_PERMANENT_FAILURE, "Unknown URL scheme");
		goto cleanup;
	}

	char *path = uripath(&uri);
	open_file(file, path);
	if (file->fp == NULL) {
		printf("[%s] No matching file found for: %s\n", client.ip, path);
		build_header(header, STATUS_NOT_FOUND, "Not found");
	} else {
		printf("[%s] Found %s\n", client.ip, file->path);
		build_header(header, STATUS_SUCCESS, file->mime_type);
	}
	free(path);

cleanup:
	uriFreeUriMembersA(&uri);
}

static int serve_request(BIO *io, Client client) {
	int ret = 0;
	char *buf[BUFSIZ];
	char header[HEADER_SIZE + 1];
	Document file = { NULL, NULL, NULL, &((struct stat) {0}) };

	prepare_response(header, &file, client);
	printf("[%s] Response header: %s", client.ip, header);

	if (BIO_puts(io, header) <= 0) {
		ret = ESSL_WRITE;
		goto cleanup;
	}
	if (file.fp != NULL) {
		while(!feof(file.fp)) {
			int wr = fread(buf, 1, BUFSIZ, file.fp);
			if (BIO_write(io, buf, wr) < 0) {
				ret = ESSL_WRITE;
				goto cleanup;
			}
		}
	}
    if (BIO_flush(io) < 0)
		ret = ESSL_WRITE;

cleanup:
	if (file.fp)
		fclose(file.fp);
	return ret;
}

static void print_version(void) {
	printf("%s %s\n", PROGNAME, VERSION);
}

static void print_help(void) {
	printf("Usage: %s [OPTIONS]... [ROOT_PATH]\n\
Serves files in ROOT_PATH via the Gemini protocol.\n\
\n\
Options:\n\
    -h           print this help message\n\
    -v           print program version information\n\
    -c PATH      certificate PATH\n\
    -k PATH      private key PATH\n\
    -p PORT      Listen on PORT\n\
    -i FILENAME  Use FILENAME as directory index\n\
    -n HOSTNAME	 Only serve requests for HOSTNAME\n\
                 (multiple hostnames are comma delimited)\n\
", PROGNAME);
}


static void parse_args(int argc, char *argv[]) {
	char c;
	while ((c = getopt(argc, argv, ":hvc:k:p:n:i:")) != -1) {
		switch (c) {
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
		case 'v':
			print_version();
			exit(EXIT_SUCCESS);
		case 'c':
			cert_path = optarg;
			break;
		case 'k':
			key_path = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			if (port < 1 || port > 65535)
				errx(1, "Option -p must be a number from 1 to 65535.");
			break;
		case 'n':
			hostname = optarg;
			break;
		case 'i':
			index_file = optarg;
			break;
		case '?':
			errx(EXIT_FAILURE, "Unknown option `-%c'.", optopt);
		case ':':
			errx(EXIT_FAILURE, "Option -%c requires an argument.", optopt);
		}
	}

	if (argv[optind] != NULL) {
		root_path = argv[optind];
	}
	root_path = realpath(root_path, NULL);
}

int main(int argc, char *argv[]) {
	int sock;
	SSL_CTX *ctx;

	parse_args(argc, argv);

	init_openssl();
	ctx = create_context();
	configure_context(ctx);
	sock = create_socket(port);

	printf("Listening on port: %d\n", port);

	/* Handle connections */
	for(;;) {
		struct sockaddr_in addr;
		unsigned int len = sizeof(addr);
		Client client;
		SSL *ssl;
		BIO *sbio;
		pid_t pid;

		int conn = accept(sock, (struct sockaddr*)&addr, &len);
		if (conn < 0) {
			perror("Unable to accept client connection");
			continue;
		}
		inet_ntop(addr.sin_family, &(addr.sin_addr), client.ip, INET6_ADDRSTRLEN);
		printf("[%s] Client connect\n", client.ip);

		if ((pid = fork())) {
			close(conn);
			printf("[%s] Forked child process %d\n", client.ip, pid);
			continue;
		}

		sbio = BIO_new_socket(conn, BIO_NOCLOSE);
		ssl = SSL_new(ctx);
		SSL_set_bio(ssl, sbio, sbio);

		if (SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
        } else {
			printf("[%s] TLS handshake complete\n", client.ip);

			BIO *io, *ssl_bio;
			io = BIO_new(BIO_f_buffer());
			ssl_bio = BIO_new(BIO_f_ssl());
			BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);
			BIO_push(io, ssl_bio);

			read_request(io, client.request);
			if (client.request == NULL) {
				fprintf(stderr, "[%s] Error reading request\n", client.ip);
			} else {
				printf("[%s] Request URL: %s\n", client.ip, client.request);
				if (serve_request(io, client) == ESSL_WRITE)
					fprintf(stderr, "[%s] SSL write error\n", client.ip);
				else
					printf("[%s] Response complete\n", client.ip);
			}
		}

		if (!SSL_shutdown(ssl)) {
			shutdown(conn, 1);
			SSL_shutdown(ssl);
		}
		SSL_free(ssl);
		close(conn);
		printf("[%s] Connection close\n", client.ip);
		return 0;
	}

	close(sock);
	SSL_CTX_free(ctx);
	cleanup_openssl();
}
