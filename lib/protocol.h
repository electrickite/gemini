/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 Corey Hinshaw
 * Released under the terms of the MIT license.
 * See LICENSE file for details.
 */
#define META_SIZE 1024
#define URL_SIZE 1024
#define REQUEST_SIZE 1026
#define HEADER_SIZE 1029
#define LINE_TERM "\r\n"
#define PATH_SEPARATOR "/"

#define GEMINI_SCHEME "gemini"
#define GEMINI_EXTENSION ".gemini"
#define GEMINI_MIME "text/gemini"
#define GEMINI_PORT 1965

#define STATUS_INPUT "10"
#define STATUS_INPUT_NAME "INPUT"
#define STATUS_SENSITIVE_INPUT "11"
#define STATUS_SENSITIVE_INPUT_NAME "SENSITIVE_INPUT"
#define STATUS_SUCCESS "20"
#define STATUS_SUCCESS_NAME "SUCCESS"
#define STATUS_SUCCESS_END_SESSION "21"
#define STATUS_SUCCESS_END_SESSION_NAME "SUCCESS - END OF CLIENT CERTIFICATE SESSION"
#define STATUS_REDIRECT_TEMPORARY "30"
#define STATUS_REDIRECT_TEMPORARY_NAME "REDIRECT - TEMPORARY"
#define STATUS_REDIRECT_PERMANENT "31"
#define STATUS_REDIRECT_PERMANENT_NAME "REDIRECT - PERMANENT"
#define STATUS_TEMPORARY_FAILURE "40"
#define STATUS_TEMPORARY_FAILURE_NAME "TEMPORARY FAILURE"
#define STATUS_SERVER_UNAVAILABLE "41"
#define STATUS_SERVER_UNAVAILABLE_NAME "SERVER UNAVAILABLE"
#define STATUS_CGI_ERROR "42"
#define STATUS_CGI_ERROR_NAME "CGI ERROR"
#define STATUS_PROXY_ERROR "43"
#define STATUS_PROXY_ERROR_NAME "PROXY ERROR"
#define STATUS_SLOW_DOWN "44"
#define STATUS_SLOW_DOWN_NAME "SLOW DOWN"
#define STATUS_PERMANENT_FAILURE "50"
#define STATUS_PERMANENT_FAILURE_NAME "PERMANENT FAILURE"
#define STATUS_NOT_FOUND "51"
#define STATUS_NOT_FOUND_NAME "NOT FOUND"
#define STATUS_GONE "52"
#define STATUS_GONE_NAME "GONE"
#define STATUS_PROXY_REFUSED "53"
#define STATUS_PROXY_REFUSED_NAME "PROXY REQUEST REFUSED"
#define STATUS_BAD_REQUEST "59"
#define STATUS_BAD_REQUEST_NAME "BAD REQUEST"
#define STATUS_CERT_REQUIRED "60"
#define STATUS_CERT_REQUIRED_NAME "CLIENT CERTIFICATE REQUIRED"
#define STATUS_TRANS_CERT_REQUESTED "61"
#define STATUS_TRANS_CERT_REQUESTED_NAME "TRANSIENT CERTIFICATE REQUESTED"
#define STATUS_AUTH_CERT_REQUIRED "62"
#define STATUS_AUTH_CERT_REQUIRED_NAME "AUTHORIZED CERTIFICATE REQUIRED"
#define STATUS_CERT_NOT_ACCEPTED "63"
#define STATUS_CERT_NOT_ACCEPTED_NAME "CERTIFICATE NOT ACCEPTED"
#define STATUS_FUTURE_CERT "64"
#define STATUS_FUTURE_CERT_NAME "FUTURE CERTIFICATE REJECTED"
#define STATUS_EXPIRED_CERT "65"
#define STATUS_EXPIRED_CERT_NAME "EXPIRED CERTIFICATE REJECTED"

