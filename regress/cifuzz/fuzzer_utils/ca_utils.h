#ifndef CA_UTILS_H
#define CA_UTILS_H

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
    This header provides utility functions for ca fuzzers.
    ca process normally runs in chroot jail on /etc/iked/
    This is not optimal to do during fuzzing for
    many reasons (overhead, chroot pivot, complexity etc.).
    Instead files and certificates from /etc/iked/ are copied to current
   directory
    (/openiked-portable/) in the fuzzing container.
    This solution while not the cleanest,
    allows us to effectively load the keys without using chroot jails.
*/

#define BUFFER_SIZE 1024
#define SOURCE_DIR "/etc/iked/"

// copies every file from source to destination
void copy_file(const char *src_path, const char *dest_path);

// copies every directory (files included) from source to destination
void copy_directory(const char *src_dir, const char *dest_dir);

// copies everything
void copy_all_files();

#endif