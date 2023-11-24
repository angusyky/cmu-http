/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the HTTP course project developed for
 * the Computer Networks course (15-441/641) taught at Carnegie
 * Mellon University.
 *
 * No part of the HTTP project may be copied and/or distributed
 * without the express permission of the 15-441/641 course staff.
 */
#ifndef PARSE_HTTP_H
#define PARSE_HTTP_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "test_error.h"

#define SUCCESS 0
#define HTTP_SIZE 4096

/* HTTP Methods */
extern const char *HEAD, *GET, *POST;

/* Request Headers */
extern char *CONTENT_LENGTH_STR, *CONNECTION_STR, *CLOSE;

/* Response Headers */
extern char *CRLF, *CONNECTION, *CONNECTION_VAL, *SERVER, *SERVER_VAL,
    *DATE, *CONTENT_TYPE, *CONTENT_LENGTH, *ZERO, *LAST_MODIFIED, *HOST;

/* Responses */
extern char *HTTP_VER, *OK, *NOT_FOUND, *SERVICE_UNAVAILABLE, *BAD_REQUEST;

/* MIME TYPES */
extern char *HTML_EXT, *HTML_MIME, *CSS_EXT, *CSS_MIME, *PNG_EXT, *PNG_MIME,
    *JPG_EXT, *JPG_MIME, *GIF_EXT, *GIF_MIME, *OCTET_MIME;

//Header field
typedef struct {
	char header_name[4096];
	char header_value[4096];
} Request_header;

//HTTP Request Header
typedef struct {
    char http_version[50];      //!< HTTP version, should be 1.1 in this project
    char http_method[50];       //!< HTTP method, could be GET, HEAD, or POSt in this project
    char http_uri[4096];        //!< HTTP URI, could be /index.html, /index.css, etc.
    char host[40];              //!< Host name, should be the IP address,
    Request_header *headers;    //!< HTTP headers, could be Content-Length, Connection, etc.
    int header_count;           //!< Number of headers
    size_t allocated_headers;   //!< Number of headers allocated
    size_t status_header_size;  //!< Size of the status line and headers
    char *body;                 //!< HTTP body, could be the content of the file
    bool valid;                 //!< Whether the request is valid
} Request;

// functions decalred in parser.y
int yyparse();
void set_parsing_options(char *buf, size_t i, Request *request);
void yyrestart();

void trim_whitespace(char *str, size_t str_len);
void to_lower(char *str, size_t str_len);
int populate_header(char *msg, char *field, const size_t field_len, char *val, const size_t val_len);

/**
 * @brief      Serialize a HTTP request from the Request struct to a buffer
 * 
 * @param      buffer  The buffer (output)
 * @param      size    The size of the buffer (output)
 * @param      request The request (input)
 * @return     the error code
 */
test_error_code_t serialize_http_request(char *buffer, size_t* size, Request *request);


/**
 * @brief      Parse a HTTP request from a buffer to a Request struct
 * 
 * @param      buffer  The buffer (input)
 * @param      size    The size of the buffer (input)
 * @param      request The request (output)
 * @return     the error code
 */
test_error_code_t parse_http_request(char *buffer, size_t size, Request * request);


/**
 * @brief      Serialize a HTTP response from the Request struct to a buffer
 * 
 * @param      msg                  The message (output)
 * @param      len                  The length of the message (output)
 * @param      prepopulated_headers The prepopulated headers (input)
 * @param      content_type         The content type (input)
 * @param      content_length       The content length (input)
 * @param      last_modified        The last modified time (input)
 * @param      body_len             The HTTP body length (input)
 * @param      body                 The HTTP body (input)
 */
test_error_code_t serialize_http_response(char **msg, size_t *len, 
    const char *prepopulated_headers, char *content_type, char *content_length, 
    char *last_modified, size_t body_len, char *body);

#endif