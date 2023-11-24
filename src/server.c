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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/mman.h>

#include "parse_http.h"
#include "ports.h"

#define MAX_OPEN_CONNS 100
#define BUF_SIZE 8192
#define CONNECTION_TIMEOUT 50

void get_filetype(char *filetype, char *filename) {
    if (strstr(filename, ".html")) {
        strcpy(filetype, HTML_MIME);
    } else if (strstr(filename, ".gif")) {
        strcpy(filetype, GIF_MIME);
    } else if (strstr(filename, ".png")) {
        strcpy(filetype, PNG_MIME);
    } else if (strstr(filename, ".jpg")) {
        strcpy(filetype, JPG_MIME);
    } else if (strstr(filename, ".css")) {
        strcpy(filetype, CSS_MIME);
    } else {
        strcpy(filetype, OCTET_MIME);
    }
}

void get_filename(char *filename, char *uri, char *www_folder) {
    size_t folder_len = strlen(www_folder);
    size_t uri_len = strlen(uri);
    strncpy(filename, www_folder, folder_len);
    strncpy(filename + folder_len, uri + 1, uri_len);
    filename[folder_len + uri_len - 1] = '\0';
}

bool lookup(char *uri, char *www_folder) {
    DIR *www_dir = opendir(www_folder);
    if (www_dir == NULL) {
        return false;
    }
    uri += 1; // Get rid of opening slash
    struct dirent *entry;
    while ((entry = readdir(www_dir)) != NULL) {
        if (strcmp(entry->d_name, uri) == 0)
            return true;
    }
    closedir(www_dir);
    return false;
}

void send_msg(int conn_fd, char *msg, size_t msg_len) {
    size_t n = 0;
    while (n < msg_len) {
        n += write(conn_fd, msg + n, msg_len - n);
    }
    printf("%s\n", msg);
    free(msg);
}

int handle_http_req(int conn_fd, char *www_folder) {
    char *msg;
    Request req;
    size_t msg_len;
    char recv_buf[BUF_SIZE], msg_headers[BUF_SIZE];
    memset(recv_buf, 0, BUF_SIZE);
    memset(msg_headers, 0, BUF_SIZE);

    size_t n = read(conn_fd, recv_buf, BUF_SIZE);
    test_error_code_t err = parse_http_request(recv_buf, n, &req);

    if (err != TEST_ERROR_NONE) {
        printf("Parse request failed\n");
        return -1;
    }

    if (strncmp(GET, req.http_method, 50) == 0) {

        // If it doesn't exist, return HTTP 404.
        if (!lookup(req.http_uri, www_folder)) {
            printf("Resource %s not found\n", req.http_uri);
            serialize_http_response(&msg, &msg_len, NOT_FOUND, NULL, NULL, NULL, 0, NULL);
            send_msg(conn_fd, msg, msg_len);
            return 0;
        }

        // If it exists, return HTTP 200.
        char filename[BUF_SIZE], filetype[BUF_SIZE], content_len[BUF_SIZE];
        get_filename(filename, req.http_uri, www_folder);
        get_filetype(filetype, filename);
        printf("Resource has filename %s with filetype %s\n", filename, filetype);

        // Get file size info
        struct stat sbuf;
        if (stat(filename, &sbuf) < 0) {
            printf("stat %s failed\n", filename);
            return -1;
        }
        size_t filesize = sbuf.st_size;
        sprintf(content_len, "%ld", filesize);

        // Borrowed mmap logic from 15213 proxy lab
        int file_fd = open(filename, O_RDONLY, 0);
        char *file_buf = mmap(0, filesize, PROT_READ, MAP_PRIVATE, file_fd, 0);
        if (file_buf == MAP_FAILED) {
            perror("mmap failed");
            close(file_fd);
            return -1;
        }
        close(file_fd);

        serialize_http_response(&msg, &msg_len, OK, filetype, content_len, NULL, filesize, file_buf);
        send_msg(conn_fd, msg, msg_len);
        return 0;
    }

    if (strncmp(HEAD, req.http_method, 50) == 0) {

        // If it doesn't exist, return HTTP 404.
        if (!lookup(req.http_uri, www_folder)) {
            printf("Resource %s not found\n", req.http_uri);
            serialize_http_response(&msg, &msg_len, NOT_FOUND, NULL, NULL, NULL, 0, NULL);
            send_msg(conn_fd, msg, msg_len);
            return 0;
        }

        // If it exists, return HTTP 200.
        char filename[BUF_SIZE], filetype[BUF_SIZE], content_len[BUF_SIZE];
        get_filename(filename, req.http_uri, www_folder);
        get_filetype(filetype, filename);
        printf("Resource has filename %s with filetype %s\n", filename, filetype);

        // Get file size info
        struct stat sbuf;
        if (stat(filename, &sbuf) < 0) {
            printf("stat %s failed\n", filename);
            return -1;
        }
        size_t filesize = sbuf.st_size;
        sprintf(content_len, "%ld", filesize);

        // Respond with empty body
        serialize_http_response(&msg, &msg_len, OK, filetype, content_len, NULL, 0, NULL);
        send_msg(conn_fd, msg, msg_len);
        return 0;
    }

    if (strncmp(POST, req.http_method, 50) == 0) {
        printf("POST CALLED\n");
        return 0;
    }

    // HTTP 400
    return 0;
}

int main(int argc, char *argv[]) {
    int optval = 1;
    int listen_fd, client_fd;
    struct sockaddr_in serv_addr, client_addr;
    unsigned int client_len = sizeof(client_addr);

    /* Validate and parse args */
    if (argc != 2) {
        fprintf(stderr, "usage: %s <www-folder>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *www_folder = argv[1];

    DIR *www_dir = opendir(www_folder);
    if (www_dir == NULL) {
        fprintf(stderr, "Unable to open www folder %s.\n", www_folder);
        return EXIT_FAILURE;
    }
    closedir(www_dir);

    // Initialize connection array as all negative (since poll() ignores negatives)
    struct pollfd open_conns[MAX_OPEN_CONNS];
    for (int i = 0; i < MAX_OPEN_CONNS; ++i) {
        open_conns[i].fd = -1;
    }

    // Set up listener socket
    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Failed to open socket");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval, sizeof(int)) < 0) {
        perror("Failed to set socket to reuse address");
        exit(EXIT_FAILURE);
    }

    if (fcntl(listen_fd, O_NONBLOCK) < 0) {
        perror("Failed to set socket as non-blocking");
        exit(EXIT_FAILURE);
    }

    memset(&serv_addr, 0, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(HTTP_PORT);

    if (bind(listen_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("Failed to bind socket");
        exit(EXIT_FAILURE);
    }

    if (listen(listen_fd, MAX_OPEN_CONNS) < 0) {
        perror("Failed to set socket to listen");
        exit(EXIT_FAILURE);
    }

    printf("Created listen fd: %d\n", listen_fd);

    while (true) {
        // Accept new connections
        memset(&client_addr, 0, sizeof(struct sockaddr_in));
        if ((client_fd = accept(listen_fd, (struct sockaddr *) &client_fd, &client_len)) > 0) {
            printf("Accepted client fd %d\n", client_fd);

            bool added = false;
            fcntl(client_fd, O_NONBLOCK);
            for (int i = 0; i < MAX_OPEN_CONNS; ++i) {
                if (open_conns[i].fd < 0) {
                    open_conns[i].fd = client_fd;
                    open_conns[i].events = POLLIN;
                    added = true;
                    printf("Added client fd %d to open connections\n", client_fd);
                    break;
                }
            }

            // Return HTTP response 503.
            if (!added) {
                perror("Max # of connections reached.");
                char *msg;
                size_t msg_len;
                serialize_http_response(&msg, &msg_len, SERVICE_UNAVAILABLE, NULL, NULL, NULL, 0, NULL);
                send_msg(client_fd, msg, msg_len);
            }
        }

        // Poll all sockets for events to handle
        poll(open_conns, MAX_OPEN_CONNS, CONNECTION_TIMEOUT);
        for (int i = 0; i < MAX_OPEN_CONNS; ++i) {
            if (open_conns[i].revents != 0) {
//                printf("Event at client fd %d\n", open_conns[i].fd);
                handle_http_req(open_conns[i].fd, www_folder);
            }
        }
    }

    return EXIT_SUCCESS;
}
