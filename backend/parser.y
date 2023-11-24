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


%{
#include "parse_http.h"

/* Define YACCDEBUG to enable debug messages for this lex file */
//#define YACCDEBUG
#define YYERROR_VERBOSE
#ifdef YACCDEBUG
#include <stdio.h>
#define YPRINTF(...) printf(__VA_ARGS__)
#else
#define YPRINTF(...)
#endif

/* yyparse() calls yyerror() on error */
void yyerror (const char *s);

void set_parsing_options(char *buf, size_t siz, Request *parsing_request);

/* yyparse() calls yylex() to get tokens */
extern int yylex();


/*
** Global variables required for parsing from buffer
** instead of stdin:
*/

/* Pointer to the buffer that contains input */
char *parsing_buf;

/* Current position in the buffer */
int parsing_offset;

/* Buffer size */
size_t parsing_buf_siz;

/* Current parsing_request Header Struct */
Request *parsing_request;

%}


/* Various types values that we can get from lex */
%union {
	char str[8192];
	int i;
}

%start request

/*
 * Tokens that yacc expects from lex, essentially these are the tokens
 * declared in declaration section of lex file.
 */
%token t_uphex
%token t_lohex
%token t_upalpha
%token t_loalpha
%token t_digit
%token t_cr
%token t_lf
%token t_sp
%token t_ht
%token t_ctl
%token t_slash
%token t_dot
%token t_colon
%token t_question
%token t_asterisk
%token t_percent
%token t_plus
%token t_minus
%token t_at
%token t_semicolon
%token t_ampersand
%token t_equal
%token t_dollar
%token t_comma
%token t_reserved_sep_no_slash
%token t_reserved_sep_slash
%token t_mark_sep
%token t_separators
%token t_mark_token
%token t_token
%token t_text
%token t_lws

/* Type of value returned for these tokens */
%type<i> t_uphex
%type<i> t_lohex
%type<i> t_upalpha
%type<i> t_loalpha
%type<i> t_digit
%type<i> t_cr
%type<i> t_lf
%type<i> t_sp
%type<i> t_ht
%type<i> t_ctl
%type<i> t_slash
%type<i> t_dot
%type<i> t_colon
%type<i> t_question
%type<i> t_asterisk
%type<i> t_percent
%type<i> t_plus
%type<i> t_minus
%type<i> t_at
%type<i> t_semicolon
%type<i> t_ampersand
%type<i> t_equal
%type<i> t_dollar
%type<i> t_comma
%type<i> t_mark_sep
%type<i> t_separators
%type<i> t_mark_token
%type<i> t_token
%type<i> t_text
%type<str> t_lws

/*
 * Followed by this, you should have types defined for all the intermediate
 * rules that you will define. These are some of the intermediate rules:
 */
%type<i> upalpha
%type<i> loalpha
%type<i> alpha
%type<i> alphanum
%type<i> ctl
%type<i> spht
%type<i> reserved_sep_no_slash
%type<i> reserved_sep
%type<i> separators
%type<i> reserved_token
%type<i> mark_token
%type<i> token_char
%type<i> text_char
%type<i> octet

%type<str> crlf
%type<str> token
%type<str> text
%type<str> field_value_part
%type<str> field_value
%type<str> http_version

%%

upalpha: t_upalpha | t_uphex {
//    printf("upalpha: %c\n", $$);
};

loalpha: t_loalpha | t_lohex {
//    printf("loalpha: %c\n", $$);
};

alpha: upalpha | loalpha {
//    printf("alpha: %c\n", $$);
};

alphanum: alpha {
//    printf("alphanum: %c\n", $$);
}; | t_digit {
    $$ = $1 + '0';
//    printf("alphanum: %c\n", $$);
};

ctl: t_ctl | t_cr | t_lf | t_ht {
//    printf("ctl\n");
}

spht: t_sp | t_ht {
//    printf("spht: %c\n", $$);
};

reserved_sep_no_slash: t_colon | t_question | t_at | t_semicolon | t_equal | t_comma {
//    printf("reserved_sep_no_slash: %c\n", $$);
};

reserved_sep: reserved_sep_no_slash | t_slash {
//    printf("reserved_sep: %c\n", $$);
};

separators: t_separators | spht | reserved_sep | t_mark_sep {
//    printf("separators: %c\n", $$);
};

reserved_token: t_plus | t_ampersand | t_dollar {
//    printf("reserved_token: %c\n", $$);
};

mark_token: t_mark_token | t_dot | t_asterisk | t_minus {
//    printf("mark_token: %c\n", $$);
};

token_char: t_token | alphanum | reserved_token | mark_token | t_percent {
//    printf("token_char: %c\n", $$);
};

text_char: t_text | token_char | t_cr | t_lf | separators {
//    printf("text_char: %c\n", $$);
};

octet: text_char | ctl {
//    printf("octet: %c\n", $$);
};

crlf: t_cr t_lf {
    $$[0] = '\r';
    $$[1] = '\n';
    $$[3] = 0;
//    printf("crlf\n");
};

token:
token_char {
	YPRINTF("token: Matched rule 1.\n");
	snprintf($$, 8192, "%c", $1);
//	printf("token: %s\n", $$);
}; |
token token_char {
	YPRINTF("token: Matched rule 2.\n");
	size_t len = strlen($1);
	memcpy($$, $1, len);
	$$[len] = $2;
	$$[len + 1] = 0;
    // snprintf($$, 8192, "%s%c", $1, $2);
//    printf("token: %s\n", $$);
};

text:
text_char {
	YPRINTF("text: Matched rule 1.\n");
	snprintf($$, 8192, "%c", $1);
//	printf("text: %s\n", $$);
}; |
text text_char {
	YPRINTF("text: Matched rule 2.\n");
	size_t len = strlen($1);
	memcpy($$, $1, len);
	$$[len] = $2;
	$$[len + 1] = 0;
    // snprintf($$, 8192, "%s%c", $1, $2);
//    printf("text: %s\n", $$);
};

field_value_part: octet {
    $$[0] = $1;
    $$[1] = 0;
//    printf("octet field_value_part: %s\n", $$);
};| t_lws {
//    printf("lws field_value_part: %s\n", $1);
};

field_value: field_value_part {
//    printf("Single field_value: %s\n", $1);
}; | field_value field_value_part {
    size_t len = strlen($1);
    memcpy($$, $1, len);
    strcpy($$ + len, $2);
//    printf("Multiple field_value: %s\n", $$);
};

request_header_part: token t_colon field_value crlf {
//    printf("request_header_part: %s:%s\n", $1, $3);

	parsing_request->header_count++;

	// Reallocate header size if necessary
	if (parsing_request->header_count > parsing_request->allocated_headers) {
	    parsing_request->allocated_headers *= 2;
	    Request_header *headers = (Request_header *) malloc(sizeof(Request_header)*parsing_request->allocated_headers);
    	for(int i = 0; i < parsing_request->header_count - 1; i++) {
    	    strcpy(headers[i].header_name, parsing_request->headers[i].header_name);
    	    strcpy(headers[i].header_value, parsing_request->headers[i].header_value);
    	}

        strcpy(headers[parsing_request->header_count - 1].header_name, $1);
    	strcpy(headers[parsing_request->header_count - 1].header_value, $3);

    	free(parsing_request->headers);
    	parsing_request->headers = headers;
	} else {
	    strcpy(parsing_request->headers[parsing_request->header_count - 1].header_name, $1);
        strcpy(parsing_request->headers[parsing_request->header_count - 1].header_value, $3);
	}

	parsing_request->status_header_size += strlen($1) + 1 + strlen($3) + 2;
}; | token t_colon crlf {
//    printf("request_header_part: %s:\n", $1);

    // Reallocate header size
	parsing_request->header_count++;

	// Reallocate header size if necessary
    if (parsing_request->header_count > parsing_request->allocated_headers) {
        parsing_request->allocated_headers *= 2;
        Request_header *headers = (Request_header *) malloc(sizeof(Request_header)*parsing_request->allocated_headers);
       	for(int i = 0; i < parsing_request->header_count - 1; i++) {
       	    strcpy(headers[i].header_name, parsing_request->headers[i].header_name);
       	    strcpy(headers[i].header_value, parsing_request->headers[i].header_value);
       	}

        strcpy(headers[parsing_request->header_count - 1].header_name, $1);
       	strcpy(headers[parsing_request->header_count - 1].header_value, "");

       	free(parsing_request->headers);
       	parsing_request->headers = headers;
    } else {
        strcpy(parsing_request->headers[parsing_request->header_count - 1].header_name, $1);
        strcpy(parsing_request->headers[parsing_request->header_count - 1].header_value, "");
    }

	parsing_request->status_header_size += strlen($1) + 1 + 2;
}

request_header: request_header_part {
//    printf("Single request_header\n");
}; | request_header request_header_part {
//    printf("Multiple request_header\n");
};

http_version: token t_slash t_digit t_dot t_digit {
    if (strcmp("HTTP", $1) == 0)
    {
        memcpy($$, $1, 4);
        $$[4] = $2;
        $$[5] = $3 + '0';
        $$[6] = $4;
        $$[7] = $5 + '0';
        $$[8] = 0;
    }
    else
    {
        $$[0] = 0;
    }
//    printf("Version: %s\n", $$);
}

request_line: token t_sp text t_sp http_version crlf {
//	printf("request_Line:\n%s %s %s\n",$1, $3,$5);
	strcpy(parsing_request->http_method, $1);
	strcpy(parsing_request->http_uri, $3);
	strcpy(parsing_request->http_version, $5);
	parsing_request->status_header_size += strlen($1) + 1 + strlen($3) + 1 + strlen($5) + 2;
}

request: request_line request_header crlf {
    YPRINTF("parsing_request: Matched Success.\n");
    parsing_request->status_header_size += 2;
    return SUCCESS;
}; | request_line crlf {
    YPRINTF("parsing_request: Matched Success.\n");
    parsing_request->status_header_size += 2;
    return SUCCESS;
}

%%

/* C code */

void set_parsing_options(char *buf, size_t siz, Request *request)
{
    parsing_buf = buf;
	parsing_offset = 0;
	parsing_buf_siz = siz;
    parsing_request = request;
}

void yyerror (const char *s) {fprintf (stderr, "%s\n", s);}
