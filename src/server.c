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
#include <signal.h>
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
#define PRINT_DBG false
#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

int get_content_len(Request *req) {
    for (int i = 0; i < req->header_count; ++i) {
        trim_whitespace(req->headers[i].header_name, strlen(req->headers[i].header_name));
        trim_whitespace(req->headers[i].header_value, strlen(req->headers[i].header_value));
        if (strcasecmp(req->headers[i].header_name, CONTENT_LENGTH_STR) == 0) {
            return atoi(req->headers[i].header_value);
        }
    }
    return 0;
}

bool check_version(Request *req) {
    trim_whitespace(req->http_version, strlen(req->http_version));
    return strcmp(req->http_version, HTTP_VER) == 0;
}

bool check_close(Request *req) {
    for (int i = 0; i < req->header_count; ++i) {
        trim_whitespace(req->headers[i].header_name, strlen(req->headers[i].header_name));
        trim_whitespace(req->headers[i].header_value, strlen(req->headers[i].header_value));
        if (strcasecmp(req->headers[i].header_name, CONNECTION_STR) == 0 &&
            strcasecmp(req->headers[i].header_value, CLOSE) == 0) {
            return true;
        }
    }
    return false;
}

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

void get_full_path(char *filename, char *www_folder, char *uri) {
    snprintf(filename, BUF_SIZE, "%s%s", www_folder, uri);
}

void append_dir_default(char *filename) {
    size_t n = strlen(filename);
    if (filename[n - 1] == '/') {
        strncat(filename, "index.html", BUF_SIZE);
    } else {
        strncat(filename, "/index.html", BUF_SIZE);
    }
}

void send_msg(int conn_fd, char *msg, size_t msg_len) {
    ssize_t n;
    ssize_t n_written = 0;
    while (n_written < msg_len) {
        int buf_size = MIN(BUF_SIZE, msg_len - n_written);
        if ((n = write(conn_fd, msg + n_written, buf_size)) < 0) {
            if (errno == EAGAIN) {
                continue;
            } else {
                perror("write");
                break;
            }
        }
        n_written += n;
    }
    free(msg);
}

void send_bad_request(int conn_fd) {
    char *msg;
    size_t msg_len;
    serialize_http_response(&msg, &msg_len, BAD_REQUEST, NULL, NULL, NULL, 0, NULL);
    send_msg(conn_fd, msg, msg_len);
}

int handle_http_req(int conn_fd, char *www_folder, Request *req, char *body) {
    char *msg;
    size_t msg_len;
    char msg_headers[BUF_SIZE];
    memset(msg_headers, 0, BUF_SIZE);

    // HTTP GET
    if (strcasecmp(GET, req->http_method) == 0) {
        char filename[BUF_SIZE], filetype[BUF_SIZE], content_len[BUF_SIZE];
        get_full_path(filename, www_folder, req->http_uri);

        // Attempt to stat the filepath
        struct stat sbuf;
        if (stat(filename, &sbuf) < 0) {
            // If it doesn't exist, return HTTP 404.
            if (PRINT_DBG) printf("stat %s failed\n", filename);
            if (PRINT_DBG) printf("Resource %s not found\n", req->http_uri);
            serialize_http_response(&msg, &msg_len, NOT_FOUND, NULL, NULL, NULL, 0, NULL);
            send_msg(conn_fd, msg, msg_len);
            return 0;
        }

        // File exists, now check if it is a directory and if it has an index.html file
        if (S_ISDIR(sbuf.st_mode)) {
            append_dir_default(filename);
            if (stat(filename, &sbuf) < 0) {
                // If it doesn't exist, return HTTP 404.
                if (PRINT_DBG) printf("stat %s failed\n", filename);
                if (PRINT_DBG) printf("Resource %s not found\n", req->http_uri);
                serialize_http_response(&msg, &msg_len, NOT_FOUND, NULL, NULL, NULL, 0, NULL);
                send_msg(conn_fd, msg, msg_len);
                return 0;
            }
        }

        // Get more information about file
        get_filetype(filetype, filename);
        size_t filesize = sbuf.st_size;
        sprintf(content_len, "%ld", filesize);

        if (PRINT_DBG) printf("Reading resource with filename %s and filetype %s\n", filename, filetype);

        // Borrowed mmap logic from 15213 proxy lab
        int file_fd = open(filename, O_RDONLY, 0);
        char *file_p = mmap(0, filesize, PROT_READ, MAP_PRIVATE, file_fd, 0);
        if (file_p == MAP_FAILED) {
            perror("mmap failed");
            close(file_fd);
            return -1;
        }
        close(file_fd);

        serialize_http_response(&msg, &msg_len, OK, filetype, content_len, NULL, filesize, file_p);
        send_msg(conn_fd, msg, msg_len);

        if (munmap(file_p, filesize) < 0) {
            perror("munmap failed");
            return -1;
        }

        return 0;
    }

    // HTTP HEAD
    if (strcasecmp(HEAD, req->http_method) == 0) {
        char filename[BUF_SIZE], filetype[BUF_SIZE], content_len[BUF_SIZE];
        get_full_path(filename, www_folder, req->http_uri);

        // Attempt to stat the filepath
        struct stat sbuf;
        if (stat(filename, &sbuf) < 0) {
            // If it doesn't exist, return HTTP 404.
            if (PRINT_DBG) printf("stat %s failed\n", filename);
            if (PRINT_DBG) printf("Resource %s not found\n", req->http_uri);
            serialize_http_response(&msg, &msg_len, NOT_FOUND, NULL, NULL, NULL, 0, NULL);
            send_msg(conn_fd, msg, msg_len);
            return 0;
        }

        // File exists, now check if it is a directory and if it has an index.html file
        if (S_ISDIR(sbuf.st_mode)) {
            append_dir_default(filename);
            if (stat(filename, &sbuf) < 0) {
                // If it doesn't exist, return HTTP 404.
                if (PRINT_DBG) printf("stat %s failed\n", filename);
                if (PRINT_DBG) printf("Resource %s not found\n", req->http_uri);
                serialize_http_response(&msg, &msg_len, NOT_FOUND, NULL, NULL, NULL, 0, NULL);
                send_msg(conn_fd, msg, msg_len);
                return 0;
            }
        }

        // Get more information about file
        get_filetype(filetype, filename);
        size_t filesize = sbuf.st_size;
        sprintf(content_len, "%ld", filesize);

        if (PRINT_DBG) printf("Reading resource with filename %s and filetype %s\n", filename, filetype);

        // Respond with empty body
        serialize_http_response(&msg, &msg_len, OK, filetype, content_len, NULL, 0, NULL);
        send_msg(conn_fd, msg, msg_len);
        return 0;
    }

    // HTTP POST
    if (strcasecmp(POST, req->http_method) == 0) {
        // Get content type and length
        int body_len;
        char *content_length, *content_type;
        for (int i = 0; i < req->header_count; ++i) {
            if (strcasecmp(req->headers[i].header_name, "Content-Length") == 0) {
                content_length = req->headers[i].header_value;
                body_len = atoi(req->headers[i].header_value);
            } else if (strcasecmp(req->headers[i].header_name, "Content-Type") == 0) {
                content_type = req->headers[i].header_value;
            }
        }

        serialize_http_response(&msg, &msg_len, OK, content_type, content_length, NULL, body_len, body);
        send_msg(conn_fd, msg, msg_len);
        return 0;
    }

    // HTTP 400
    send_bad_request(conn_fd);
    return 0;
}

int main(int argc, char *argv[]) {
    int optval = 1;
    int listen_fd, client_fd;
    struct sockaddr_in serv_addr, client_addr;
    unsigned int client_len = sizeof(client_addr);

    signal(SIGPIPE, SIG_IGN);

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

    // remove trailing slash
    size_t folder_len = strlen(www_folder);
    if (www_folder[folder_len - 1] == '/') {
        www_folder[folder_len - 1] = '\0';
    }

    // Initialize connection array as all negative (since poll() ignores negatives)
    long conn_timeouts[MAX_OPEN_CONNS];
    struct pollfd open_conns[MAX_OPEN_CONNS];
    for (int i = 0; i < MAX_OPEN_CONNS; ++i) {
        open_conns[i].fd = -1;
        conn_timeouts[i] = 0;
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

    if (fcntl(listen_fd, F_SETFL, fcntl(listen_fd, F_GETFL, 0) | O_NONBLOCK) < 0) {
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

    if (PRINT_DBG) printf("Created listen fd: %d\n", listen_fd);

    while (true) {

        // Accept new connections
        memset(&client_addr, 0, sizeof(struct sockaddr_in));
        if ((client_fd = accept(listen_fd, (struct sockaddr *) &client_addr, &client_len)) > 0) {

            if (PRINT_DBG) printf("Accepted client fd %d\n", client_fd);

            // Search for open connection slot to use
            bool added = false;
            fcntl(client_fd, F_SETFL, fcntl(client_fd, F_GETFL, 0) | O_NONBLOCK);
            for (int i = 0; i < MAX_OPEN_CONNS; ++i) {
                if (open_conns[i].fd < 0) {
                    conn_timeouts[i] = time(NULL);
                    open_conns[i].fd = client_fd;
                    open_conns[i].events = POLLIN;
                    added = true;
                    break;
                }
            }

            // Return HTTP response 503
            if (!added) {
                perror("Max # of connections reached.");
                char *msg;
                size_t msg_len;
                serialize_http_response(&msg, &msg_len, SERVICE_UNAVAILABLE, NULL, NULL, NULL, 0, NULL);
                send_msg(client_fd, msg, msg_len);
            }
        }

        // Poll all sockets for events to handle
        poll(open_conns, MAX_OPEN_CONNS, 1000);
        for (int i = 0; i < MAX_OPEN_CONNS; ++i) {
            int conn_fd = open_conns[i].fd;
            if (open_conns[i].revents & POLLIN) {

                // Reset timeout
                conn_timeouts[i] = time(NULL);

                // Peek at socket
                char recv_buf[BUF_SIZE];
                memset(recv_buf, 0, BUF_SIZE);
                ssize_t n = recv(conn_fd, recv_buf, BUF_SIZE, MSG_PEEK);

                // Close socket if client has closed on their side
                if (n <= 0) {
                    if (PRINT_DBG) printf("closing fd %d\n", conn_fd);
                    open_conns[i].fd = -1;
                    close(conn_fd);
                    continue;
                }

                if (PRINT_DBG) printf("%s\n", recv_buf);

                // Parse read buf into request struct
                Request req;
                test_error_code_t err = parse_http_request(recv_buf, n, &req);
                if (err != TEST_ERROR_NONE) {
                    send_bad_request(conn_fd);
                    continue;
                }

                // read() first header_size bytes to drain from socket
                read(conn_fd, recv_buf, req.status_header_size);

                // Get content length to allocate buffer for content length
                int content_len = get_content_len(&req);
                read(conn_fd, recv_buf, content_len);
                if (PRINT_DBG) printf("content length is %d\n", content_len);

                // Validate well-formed HTTP request
                if (!check_version(&req)) {
                    send_bad_request(conn_fd);
                } else {
                    handle_http_req(conn_fd, www_folder, &req, recv_buf);
                }

                // Close connection if client requests it
                if (check_close(&req)) {
                    open_conns[i].fd = -1;
                    close(conn_fd);
                }

            } else {
//                // Check timeout
//                if (open_conns[i].fd > 0 && (time(NULL) - conn_timeouts[i] >= CONNECTION_TIMEOUT)) {
//                    if (PRINT_DBG) printf("closing fd %d\n", conn_fd);
//                    open_conns[i].fd = -1;
//                    close(conn_fd);
//                }
            }
        }
    }

    return EXIT_SUCCESS;
}
