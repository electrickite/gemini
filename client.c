#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 500
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#include <uriparser/Uri.h>
#include "lib/common.h"
#include "lib/protocol.h"
#include "lib/uriutil.h"
#include "version.h"

#define PROGNAME "glv"

#define SCHEME_SEP "://"

static char *rawUrl;
static UriUriA uri;
static char *uriString;
static char *host;
static char *port = STRINGIFY(GEMINI_PORT);
const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS";

void init_openssl_library(void) {
	(void)SSL_library_init();
	SSL_load_error_strings();
}

void print_error_string(unsigned long err, const char* const label) {
	const char* const str = ERR_reason_error_string(err);
	if (str)
		fprintf(stderr, "%s\n", str);
	else
		fprintf(stderr, "%s failed: %lu (0x%lx)\n", label, err, err);
}

static void print_version(void) {
	printf("%s %s\n", PROGNAME, VERSION);
}

static void print_help(void) {
	printf("Usage: %s [OPTIONS]... URL\n\
Fetch URL via the Gemini protocol and display on standard output.\n\
\n\
Options:\n\
    -h           print this help message\n\
    -v           print program version information\n\
", PROGNAME);
}

static void parse_url_arg(char *urlarg) {
	const char *uriErrorPos;
	int charsRequired;

	if (strstr(urlarg, SCHEME_SEP) != NULL) {
		rawUrl = strdup(urlarg);
	} else {
		rawUrl = malloc((strlen(GEMINI_SCHEME) + strlen(SCHEME_SEP) + strlen(urlarg) + 1) * sizeof(char));
		strcpy(rawUrl, GEMINI_SCHEME SCHEME_SEP);
		strcat(rawUrl, urlarg);
	}

	if (uriParseSingleUriA(&uri, rawUrl, &uriErrorPos) != URI_SUCCESS
			|| uriNormalizeSyntaxA(&uri) != URI_SUCCESS) {
		errx(EXIT_FAILURE, "Invalid URL!");
	} else if (uriNormalizeSyntaxA(&uri) != URI_SUCCESS) {
		errx(EXIT_FAILURE, "Error normalizing URL!!");
	} else if (urilen(&uri.hostText) == 0) {
		errx(EXIT_FAILURE, "URL does not contain host name!");
	}

	if (uricmp(&uri.scheme, GEMINI_SCHEME) != 0) {
		errx(EXIT_FAILURE, "URL scheme must be " GEMINI_SCHEME);
	} else if (urilen(&uri.scheme) == 0) {
		const char *scheme = GEMINI_SCHEME;
		uri.scheme.first = scheme;
		uri.scheme.afterLast = scheme + strlen(scheme);
	}

	if (uriToStringCharsRequiredA(&uri, &charsRequired) != URI_SUCCESS) {
		errx(EXIT_FAILURE, "Error calculating URI composition");
	}
	charsRequired++;
	uriString = malloc(charsRequired * sizeof(char));
	if (uriString == NULL || uriToStringA(uriString, &uri, charsRequired, NULL) != URI_SUCCESS) {
		errx(EXIT_FAILURE, "Error composing URI");
	}
	if (strlen(uriString) > URL_SIZE) {
		errx(EXIT_FAILURE, "URL exceeds maximum length of " STRINGIFY(URL_SIZE) " bytes.");
	}

	host = uridup(&uri.hostText);
	if (urilen(&uri.portText) > 0) {
		port = uridup(&uri.portText);
	}
}

static void parse_args(int argc, char *argv[]) {
	char c;
	while ((c = getopt(argc, argv, ":hv")) != -1) {
		switch (c) {
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
		case 'v':
			print_version();
			exit(EXIT_SUCCESS);
		case '?':
			errx(EXIT_FAILURE, "Unknown option `-%c'.", optopt);
		case ':':
			errx(EXIT_FAILURE, "Option -%c requires an argument.", optopt);
		}
	}

	if (argv[optind] == NULL) {
		errx(EXIT_FAILURE, "URL not provided.");
	}
	parse_url_arg(argv[optind]);
}

int main(int argc, char *argv[]) {
	long res = 1;
	int ret = 1;
	unsigned long ssl_err = 0;

	SSL_CTX* ctx = NULL;
	BIO *gem = NULL, *out = NULL;
	SSL *ssl = NULL;

	parse_args(argc, argv);

	do {
		init_openssl_library();
		const SSL_METHOD* method = SSLv23_method();
		ssl_err = ERR_get_error();
		if(NULL == method) {
			print_error_string(ssl_err, "SSLv23_method");
			break;
		}

		ctx = SSL_CTX_new(method);
		ssl_err = ERR_get_error();
		if(ctx == NULL) {
			print_error_string(ssl_err, "SSL_CTX_new");
			break;
		}

		const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
		SSL_CTX_set_verify_depth(ctx, 5);
		SSL_CTX_set_options(ctx, flags);

		gem = BIO_new_ssl_connect(ctx);
		ssl_err = ERR_get_error();
		if(!(gem != NULL)) {
			print_error_string(ssl_err, "BIO_new_ssl_connect");
			break; /* failed */
		}

		res = BIO_set_conn_hostname(gem, host);
		ssl_err = ERR_get_error();
		if(!(1 == res)) {
			print_error_string(ssl_err, "BIO_set_conn_hostname");
			break; /* failed */
		}

		res = BIO_set_conn_port(gem, port);
		ssl_err = ERR_get_error();
		if(!(1 == res)) {
			print_error_string(ssl_err, "BIO_set_conn_port");
			break; /* failed */
		}

		BIO_get_ssl(gem, &ssl);
		ssl_err = ERR_get_error();
		if(!(ssl != NULL)) {
			print_error_string(ssl_err, "BIO_get_ssl");
			break; /* failed */
		}

		res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
		ssl_err = ERR_get_error();
		if(!(1 == res)) {
			print_error_string(ssl_err, "SSL_set_cipher_list");
			break; /* failed */
		}

		res = SSL_set_tlsext_host_name(ssl, host);
		ssl_err = ERR_get_error();
		if(!(1 == res)) {
			print_error_string(ssl_err, "SSL_set_tlsext_host_name");
			/* No fail */
		}

		out = BIO_new_fp(stdout, BIO_NOCLOSE);
		ssl_err = ERR_get_error();
		if(!(NULL != out)) {
			print_error_string(ssl_err, "BIO_new_fp");
			break; /* failed */
		}

		res = BIO_do_connect(gem);
		ssl_err = ERR_get_error();
		if(!(1 == res)) {
			print_error_string(ssl_err, "BIO_do_connect");
			break; /* failed */
		}

		res = BIO_do_handshake(gem);
		ssl_err = ERR_get_error();
		if(!(1 == res)) {
			print_error_string(ssl_err, "BIO_do_handshake");
			break; /* failed */
		}

		/* X509 verification */
		/* Step 1: verify a server certifcate was presented during negotiation */
		X509* cert = SSL_get_peer_certificate(ssl);
		if(cert) { X509_free(cert); } /* Free immediately */
		if(NULL == cert) {
			print_error_string(X509_V_ERR_APPLICATION_VERIFICATION, "SSL_get_peer_certificate");
			break; /* failed */
		}

		/* Step 2: verify the result of chain verifcation             */
		/*
		res = SSL_get_verify_result(ssl);
		if(!(X509_V_OK == res)) {
			print_error_string((unsigned long)res, "SSL_get_verify_results");
			break;
		}
		*/

		/* Step 3: hostname verifcation.   */
		/* An exercise left to the reader. */

		BIO_puts(gem, uriString);
		BIO_puts(gem, LINE_TERM);

		int len = 0;
		do {
			char buff[1536] = {0};
			len = BIO_read(gem, buff, sizeof(buff));

			if (len > 0)
				BIO_write(out, buff, len);
		} while (len > 0 || BIO_should_retry(gem));

		ret = 0;
	} while (0);

	if(out)
		BIO_free(out);
	if(gem != NULL)
		BIO_free_all(gem);
	if(NULL != ctx)
		SSL_CTX_free(ctx);

	return ret;
}
