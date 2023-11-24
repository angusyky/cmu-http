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
/* HTTP Methods */
const char *HEAD = "HEAD";
const char *GET = "GET";
const char *POST = "POST";

/* Request Headers */
char *CONTENT_LENGTH_STR = "content-length";
char *CONNECTION_STR = "connection";
char *CLOSE = "close";

/* Response Headers */
char *CRLF = "\r\n";

char *CONNECTION = "Connection:";
char *CONNECTION_VAL = "Keep-Alive";

char *SERVER = "Server: ";
char *SERVER_VAL = "cmu/1.0";

char *DATE = "Date: ";
char *CONTENT_TYPE = "Content-Type: ";
char *CONTENT_LENGTH = "Content-Length: ";
char *ZERO = "0";

char *LAST_MODIFIED = "Last-Modified: ";
char *HOST = "Host: ";

/* Status Lines */
char *HTTP_VER = "HTTP/1.1";
char *OK = "200 OK\r\n";
char *NOT_FOUND = "404 Not Found\r\n";
char *SERVICE_UNAVAILABLE = "503 Service Unavailable\r\n";
char *BAD_REQUEST = "400 Bad Request\r\n";

/* MIME TYPES */
char *HTML_EXT = "html";
char *HTML_MIME = "text/html";

char *CSS_EXT = "css";
char *CSS_MIME = "text/css";

char *PNG_EXT = "png";
char *PNG_MIME = "image/png";

char *JPG_EXT = "jpg";
char *JPG_MIME = "image/jpeg";

char *GIF_EXT = "gif";
char *GIF_MIME = "image/gif";

char *OCTET_MIME = "application/octet-stream";
