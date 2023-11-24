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
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include <parse_http.h>
#include <test_error.h>
#include <ports.h>

int main(int argc, char *argv[]) {
    /* Validate and parse args */
    if (argc != 2) {
        fprintf(stderr, "usage: %s <server-ip>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    /* Set up a connection to the HTTP server */
    int http_sock;
    struct sockaddr_in http_server;
    if ((http_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return TEST_ERROR_HTTP_CONNECT_FAILED;
    }
    http_server.sin_family = AF_INET;
    http_server.sin_port = htons(HTTP_PORT);
    inet_pton(AF_INET, argv[1], &(http_server.sin_addr));
    
    fprintf(stderr, "Parsed IP address of the server: %X\n", htonl(http_server.sin_addr.s_addr));

    if (connect (http_sock, (struct sockaddr *)&http_server, sizeof(http_server)) < 0){
        return TEST_ERROR_HTTP_CONNECT_FAILED;
    }

    /* CP1: Send out a HTTP request, waiting for the response */

}