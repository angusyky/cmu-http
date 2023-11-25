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
#define PRINT_DBG false

int is_dir(const char *filename) {
    struct stat sbuf;
    if (stat(filename, &sbuf) != 0) {
        perror("stat failed\n");
        return 0;
    }
    return S_ISDIR(sbuf.st_mode);
}

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
    if (PRINT_DBG) printf("%s\n", msg);
    free(msg);
}

int handle_http_req(int conn_fd, char *www_folder, Request *req, char *recv_buf) {
    char *msg;
    size_t msg_len;
    char msg_headers[BUF_SIZE];
    memset(msg_headers, 0, BUF_SIZE);

    // HTTP GET
    if (strcasecmp(GET, req->http_method) == 0) {
        char filename[BUF_SIZE], filetype[BUF_SIZE], content_len[BUF_SIZE];

        // If directory, default to index.html
        get_filename(filename, req->http_uri, www_folder);
        if (is_dir(filename)) {
            size_t uri_len = strlen(req->http_uri);
            if (req->http_uri[uri_len - 1] == '/') {
                strcat(req->http_uri, "index.html");
            } else {
                strcat(req->http_uri, "/index.html");
            }
        }

        // Get more information about resource
        get_filename(filename, req->http_uri, www_folder);
        get_filetype(filetype, filename);

        if (PRINT_DBG) printf("Resource has filename %s with filetype %s\n", filename, filetype);

        // Get file size info
        struct stat sbuf;
        if (stat(filename, &sbuf) < 0) {
            // If it doesn't exist, return HTTP 404.
            if (errno == ENOENT) {
                if (PRINT_DBG) printf("Resource %s not found\n", req->http_uri);
                serialize_http_response(&msg, &msg_len, NOT_FOUND, NULL, NULL, NULL, 0, NULL);
                send_msg(conn_fd, msg, msg_len);
                return 0;
            } else {
                if (PRINT_DBG) printf("stat %s failed\n", filename);
                return -1;
            }
        }
        size_t filesize = sbuf.st_size;
        sprintf(content_len, "%ld", filesize);

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

        // If directory, default to index.html
        get_filename(filename, req->http_uri, www_folder);
        if (is_dir(filename)) {
            size_t uri_len = strlen(req->http_uri);
            if (req->http_uri[uri_len - 1] == '/') {
                strcat(req->http_uri, "index.html");
            } else {
                strcat(req->http_uri, "/index.html");
            }
        }

        // Get more information about resource
        get_filename(filename, req->http_uri, www_folder);
        get_filetype(filetype, filename);

        if (PRINT_DBG) printf("Resource has filename %s with filetype %s\n", filename, filetype);

        // Get file size info
        struct stat sbuf;
        if (stat(filename, &sbuf) < 0) {
            // If it doesn't exist, return HTTP 404.
            if (errno == ENOENT) {
                if (PRINT_DBG) printf("Resource %s not found\n", req->http_uri);
                serialize_http_response(&msg, &msg_len, NOT_FOUND, NULL, NULL, NULL, 0, NULL);
                send_msg(conn_fd, msg, msg_len);
                return 0;
            } else {
                if (PRINT_DBG) printf("stat %s failed\n", filename);
                return -1;
            }
        }
        size_t filesize = sbuf.st_size;
        sprintf(content_len, "%ld", filesize);

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

        // Set the request body ourselves since the parsing API does not
        char *body = recv_buf + req->status_header_size;

        serialize_http_response(&msg, &msg_len, OK, content_type, content_length, NULL, body_len, body);
        send_msg(conn_fd, msg, msg_len);
        return 0;
    }

    // HTTP 400
    serialize_http_response(&msg, &msg_len, BAD_REQUEST, NULL, NULL, NULL, 0, NULL);
    send_msg(conn_fd, msg, msg_len);
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

                // Try to read from socket
                char recv_buf[BUF_SIZE];
                memset(recv_buf, 0, BUF_SIZE);
                ssize_t n = read(conn_fd, recv_buf, BUF_SIZE);
                if (n == 0) {
                    if (PRINT_DBG) printf("closing fd %d\n", conn_fd);
                    open_conns[i].fd = -1;
                    close(conn_fd);
                    continue;
                } else if (n < 0) {
                    perror("read");
                    continue;
                }
                if (PRINT_DBG) printf("%s\n", recv_buf);

                // Parse read buf into request struct and check http version
                Request req;
                test_error_code_t err = parse_http_request(recv_buf, n, &req);
                if (err != TEST_ERROR_NONE || !check_version(&req)) {
                    char *msg;
                    size_t msg_len;
                    serialize_http_response(&msg, &msg_len, BAD_REQUEST, NULL, NULL, NULL, 0, NULL);
                    send_msg(conn_fd, msg, msg_len);
                    continue;
                }

                handle_http_req(conn_fd, www_folder, &req, recv_buf);

                // Close connection if client requests it
                if (check_close(&req)) {
                    open_conns[i].fd = -1;
                    close(conn_fd);
                }

            } else {
                // Check timeout
                if (open_conns[i].fd > 0 && (time(NULL) - conn_timeouts[i] >= CONNECTION_TIMEOUT)) {
                    if (PRINT_DBG) printf("closing fd %d\n", conn_fd);
                    open_conns[i].fd = -1;
                    close(conn_fd);
                }
            }
        }
    }

    return EXIT_SUCCESS;
}
