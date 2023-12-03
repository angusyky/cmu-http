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
#include <errno.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <fcntl.h>

#define BUF_SIZE 8192
#define MAX_CONNECTIONS 1
#define PRINT_DBG false

uint32_t time_ms() {
    struct timespec time;
    timespec_get(&time, TIME_UTC);
    return ((uint32_t)time.tv_sec) * 1000 + ((uint32_t)time.tv_nsec) / 1000000;
}

typedef enum {
    START = 0, RECV_DEPENDENCY, FETCHING
} client_status_t;

typedef enum {
    NOT_READY = 0, READY, REQUESTED, SAVED
} file_status_t;

typedef struct {
    int status_code;
    long total_length;
    long content_length;
    char *body;
} Response;

typedef struct {
    size_t total_size;
    ssize_t n_read;
    int file_id;
    char *uri;
    char *buf;
} response_info;

void send_msg(int conn_fd, char *msg, size_t msg_len) {
    ssize_t n;
    ssize_t n_written = 0;
    while (n_written < msg_len) {
        if ((n = write(conn_fd, msg + n_written, msg_len)) < 0) {
            if (errno == EAGAIN) {
                continue;
            } else {
                perror("write");
                break;
            }
        }
        n_written += n;
    }
    if (PRINT_DBG) {
        printf("N_WRITTEN: %ld\n", n_written);
        printf("SEND MESSAGE -> FD %d\n", conn_fd);
        printf("MSG_LEN: %ld\n", msg_len);
        printf("%s\n", msg);
        printf("\n");
    }
}

void request_uri(int conn_fd, const char *uri) {
    Request req;
    size_t msg_len = 0;
    char msg[BUF_SIZE];
    strncpy(req.http_uri, uri, 4096);
    strncpy(req.http_version, HTTP_VER, 50);
    strncpy(req.http_method, GET, 50);
    strncpy(req.host, "cmu-http client", 40);
    req.header_count = 0;
    serialize_http_request(msg, &msg_len, &req);
    send_msg(conn_fd, msg, msg_len);
}

void reset_res_info(response_info *ri) {
    if (ri->buf != NULL) {
        free(ri->buf);
    }
    if (ri->uri != NULL) {
        free(ri->uri);
    }
    ri->uri = NULL;
    ri->buf = NULL;
    ri->total_size = 0;
    ri->file_id = -1;
    ri->n_read = 0;
}


void write_to_file(const char *filename, const char *buf, size_t size) {
    FILE *file = fopen(filename, "wb+");
    if (file == NULL) {
        perror("Error opening or creating file");
        exit(EXIT_FAILURE);
    }

    size_t n = fwrite(buf, sizeof(char), size, file);
    if (n != size) {
        fprintf(stderr, "Error writing to file\n");
        exit(EXIT_FAILURE);
    }

    fclose(file);
}

void get_uri_filename(char *filename, char *directory, char *uri) {
    snprintf(filename, BUF_SIZE, "%s%s", directory, uri);
}

int get_file_id(const char *file, char **files, int n_files) {
    for (int i = 0; i < n_files; ++i) {
        if (strcasecmp(file, files[i]) == 0) {
            return i;
        }
    }
    return -1;
}

int process_dependencies(char ***files, file_status_t **file_status, int **dependencies) {
    // Open the CSV file for reading
    FILE *file = fopen("./www/dependency.csv", "r");
    if (file == NULL) {
        perror("Error opening dependency file");
        exit(EXIT_FAILURE);
    }

    // Count number of files
    int n_files = 0;
    char line[BUF_SIZE];
    while (fgets(line, sizeof(line), file) != NULL) {
        n_files++;
    }

    // Allocate space for all files
    if (PRINT_DBG) fprintf(stderr, "%d files in dependency.csv\n", n_files);
    *files = calloc(n_files, sizeof(char *));
    *file_status = calloc(n_files, sizeof(file_status_t));
    *dependencies = calloc(n_files, sizeof(int));

    rewind(file);
    // Assign each file to a slot
    int i = 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        char *line_copy = strdup(line);
        char *item = strtok(line_copy, ",\n");
        char *dependency = strtok(NULL, ",\n");
        (*files)[i] = strdup(item);
        if (dependency == NULL) {
            (*file_status)[i] = READY;
        } else {
            (*file_status)[i] = NOT_READY;
        }
        free(line_copy);
        ++i;
    }

    rewind(file);

    // Assign each file to its dependency
    i = 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        char *line_copy = strdup(line);
        char *item = strtok(line_copy, ",\n");
        char *dependency = strtok(NULL, ",\n");
        if (dependency == NULL) {
            (*dependencies)[i] = -1;
        } else {
            trim_whitespace(dependency, strlen(dependency));
            (*dependencies)[i] = get_file_id(dependency, *files, n_files);
        }
        free(line_copy);
        ++i;
    }

    // Close the file
    fclose(file);
    return n_files;
}

bool all_files_saved(const file_status_t *file_status, int n_files) {
    for (int i = 0; i < n_files; ++i) {
        if (file_status[i] != SAVED) {
            return false;
        }
    }
    return true;
}

int parse_http_response(Response *response, const char *buf) {
    char status_message[BUF_SIZE];

    // Parse status code and message
    const char *status_line = strstr(buf, "HTTP/1.1");
    if (status_line == NULL) {
        fprintf(stderr, "No status line\n");
        return -1;
    } else {
        sscanf(status_line, "HTTP/1.1 %d %s", &response->status_code, status_message);
    }

    // Parse content length
    const char *content_length_line = strstr(buf, CONTENT_LENGTH);
    if (content_length_line == NULL) {
        response->content_length = 0;
    } else {
        sscanf(content_length_line, "Content-Length: %ld", &response->content_length);
    }

    // Allocate memory for content and copy it
    const char *body_start = strstr(buf, "\r\n\r\n") + 4;
    if (body_start == NULL) {
        fprintf(stderr, "Response incomplete\n");
        return -1;
    }

    const char *content_end = body_start + response->content_length;
    long total_length = ((char *) content_end) - ((char *) buf);
    response->total_length = total_length;
    return 0;
}

// Function to print the parsed response
void print_response(Response *response) {
    printf("\nRESPONSE\n");
    printf("Status Code: %d\n", response->status_code);
    printf("Content-Length: %ld\n", response->content_length);
    printf("Total Size: %ld\n", response->total_length);
    printf("\n");
}

void print_ri(response_info *ri) {
    printf("\nRESPONSE INFO\n");
    printf("URI: %s\n", ri->uri);
    printf("FILE: %d\n", ri->file_id);
    printf("TOTALSIZE: %ld\n", ri->total_size);
    printf("N_READ: %ld\n", ri->n_read);
    printf("BUF: %s\n", ri->buf);
    printf("\n");
}

int main(int argc, char *argv[]) {
    ssize_t n;
    Request req;
    Response res;
    size_t msg_len;
    char *dir_name = "./www";
    char msg[BUF_SIZE], recv_buf[BUF_SIZE], uri[BUF_SIZE], filename[BUF_SIZE];
    int conn_idx = 0;
    struct pollfd open_conns[MAX_CONNECTIONS];
    response_info conn_responses[MAX_CONNECTIONS];
    char **files = NULL;
    int n_files = 0;
    int *dependencies = NULL;
    file_status_t *file_status = NULL;
    client_status_t state = START;

    /* Validate and parse args */
    if (argc != 2) {
        fprintf(stderr, "usage: %s <server-ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Create dir if it doesn't exist
    struct stat sbuf;
    if (stat(dir_name, &sbuf) == -1) {
        mkdir(dir_name, 0700);
    }

    // Initialize data structures and connections
    for (int i = 0; i < MAX_CONNECTIONS; ++i) {
        /* Set up a connection to the HTTP server */
        int http_sock;
        struct sockaddr_in http_server;
        if ((http_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            return TEST_ERROR_HTTP_CONNECT_FAILED;
        }

        http_server.sin_family = AF_INET;
        http_server.sin_port = htons(HTTP_PORT);
        inet_pton(AF_INET, argv[1], &(http_server.sin_addr));

        if (connect(http_sock, (struct sockaddr *) &http_server, sizeof(http_server)) < 0) {
            return TEST_ERROR_HTTP_CONNECT_FAILED;
        }

        conn_responses[i].uri = NULL;
        conn_responses[i].buf = NULL;
        conn_responses[i].total_size = 0;
        conn_responses[i].n_read = 0;
        conn_responses[i].file_id = -1;
        open_conns[i].fd = http_sock;
        open_conns[i].events = POLLIN;
    }

    printf("START_TIME %d\n", time_ms());

    /* CP1: Send out a HTTP request, waiting for the response */
    while (true) {
        if (state == START) {
            // Ask for dependency csv
            strncpy(req.http_uri, "/dependency.csv", 4096);
            strncpy(req.http_version, HTTP_VER, 50);
            strncpy(req.http_method, GET, 50);
            strncpy(req.host, "cmu-http client", 40);
            req.header_count = 0;
            serialize_http_request(msg, &msg_len, &req);
            send_msg(open_conns[0].fd, msg, msg_len);
            state = RECV_DEPENDENCY;
        }

        if (state == RECV_DEPENDENCY) {
            // Peek at socket to receive dependency csv
            n = recv(open_conns[0].fd, recv_buf, BUF_SIZE, MSG_PEEK);

            // Server closed socket
            if (n <= 0) {
                perror("recv");
                exit(EXIT_FAILURE);
            }

            // Parse response
            int err = parse_http_response(&res, recv_buf);
            if (err < 0) {
                continue;
            }

            // Allocate space for dependency graph if first time successfully parsing
            response_info *ri = &conn_responses[0];
            if (ri->buf == NULL) {
                ri->uri = strdup("/dependency.csv");
                ri->buf = calloc(res.total_length, sizeof(char));
                ri->total_size = res.total_length;
                ri->n_read = 0;
            }

            // Get the whole dependency response
            if (ri->n_read != ri->total_size) {
                n = read(open_conns[0].fd, ri->buf + ri->n_read, ri->total_size - ri->n_read);
                ri->n_read += n;
            }

            // If all information is here, save and parse dependency graph
            if (ri->n_read == ri->total_size) {
                err = parse_http_response(&res, ri->buf);
                if (err < 0) {
                    fprintf(stderr, "Fully received response cannot parse correctly!\n");
                    exit(EXIT_FAILURE);
                }
                get_uri_filename(filename, dir_name, ri->uri);
                write_to_file(filename, ri->buf + (res.total_length - res.content_length), res.content_length);
                n_files = process_dependencies(&files, &file_status, &dependencies);
                reset_res_info(ri);
                state = FETCHING;
            }
        }

        // Only enter below code if we are ready to get all our dependencies
        if (state != FETCHING) {
            continue;
        }

        // Check which files we can request
        for (int i = 0; i < n_files; ++i) {
            if (file_status[i] == READY) {
                conn_idx = (conn_idx + 1) % MAX_CONNECTIONS;
                int conn_fd = open_conns[conn_idx].fd;

                if (conn_responses[conn_idx].uri != NULL)
                    continue;

                snprintf(uri, BUF_SIZE, "/%s", files[i]);
                conn_responses[conn_idx].uri = strdup(uri);
                conn_responses[conn_idx].file_id = i;
                request_uri(conn_fd, uri);
                file_status[i] = REQUESTED;
            }
        }

        // Poll to receive data
        poll(open_conns, MAX_CONNECTIONS, 0);
        for (int conn_id = 0; conn_id < MAX_CONNECTIONS; ++conn_id) {
            int conn_fd = open_conns[conn_id].fd;
            if (open_conns[conn_id].revents & POLLIN) {
                response_info *ri = &conn_responses[conn_id];

                // Peek at socket
                n = recv(conn_fd, recv_buf, BUF_SIZE, MSG_PEEK);

                // Close socket if client has closed on their side
                if (n <= 0) {
                    if (PRINT_DBG) printf("closing fd %d\n", conn_fd);
                    reset_res_info(ri);
                    open_conns[conn_id].fd = -1;
                    close(conn_fd);
                    continue;
                }

                // Start new response if none in progress
                if (ri->buf == NULL) {
                    // Parse response
                    int err = parse_http_response(&res, recv_buf);
                    if (err < 0) {
                        if (PRINT_DBG) printf("PARTIAL RESPONSE\n");
                        continue;
                    }
                    // Allocate space for dependency graph if first time successfully parsing
                    ri->buf = calloc(res.total_length, sizeof(char));
                    ri->total_size = res.total_length;
                    ri->n_read = 0;
                }

                // Read rest of response still only partially read
                if (ri->n_read != ri->total_size) {
                    n = read(conn_fd, ri->buf + ri->n_read, ri->total_size - ri->n_read);
                    ri->n_read += n;
                }

                // If all information is here, save and parse graph
                if (ri->n_read == ri->total_size) {
                    int err = parse_http_response(&res, ri->buf);;
                    if (err < 0) {
                        fprintf(stderr, "Fully received response cannot parse correctly!\n");
                        exit(EXIT_FAILURE);
                    }
                    get_uri_filename(filename, dir_name, ri->uri);
                    write_to_file(filename, ri->buf + (res.total_length - res.content_length), res.content_length);

                    // Set all dependent files to ready
                    file_status[ri->file_id] = SAVED;
                    for (int j = 0; j < n_files; ++j) {
                        if (file_status[j] == NOT_READY && dependencies[j] == ri->file_id) {
                            file_status[j] = READY;
                        }
                    }

                    // Release resources for this connection, so it can handle another response
                    reset_res_info(ri);
                }
            }
        }

        // Check if all files are saved
        if (all_files_saved(file_status, n_files)) {
            break;
        }
    }

    printf("END_TIME %d\n", time_ms());
    
    for (int i = 0; i < n_files; ++i) {
        free(files[i]);
    }
    free(files);
    free(file_status);
    free(dependencies);
}