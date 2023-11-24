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

#include "parse_http.h"
#include "ports.h"

#define BUF_SIZE 8192
#define CONNECTION_TIMEOUT 50

int main(int argc, char *argv[]) {
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

    /* CP1: Set up sockets and read the buf */
    return EXIT_SUCCESS;
}
