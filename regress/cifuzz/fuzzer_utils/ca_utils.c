#include "ca_utils.h"

#define BUFFER_SIZE 1024
#define SOURCE_DIR "/etc/iked/"

void copy_file(const char *src_path, const char *dest_path) {
    int src_fd = open(src_path, O_RDONLY);
    if (src_fd == -1) {
        perror("Failed to open source file");
        return;
    }

    int dest_fd = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC,
                       S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (dest_fd == -1) {
        perror("Failed to open destination file");
        close(src_fd);
        return;
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read, bytes_written;

    while ((bytes_read = read(src_fd, buffer, BUFFER_SIZE)) > 0) {
        bytes_written = write(dest_fd, buffer, bytes_read);
        if (bytes_written != bytes_read) {
            perror("Failed to write to destination file");
            close(src_fd);
            close(dest_fd);
            return;
        }
    }

    if (bytes_read == -1) {
        perror("Failed to read from source file");
    }

    close(src_fd);
    close(dest_fd);
}

void copy_directory(const char *src_dir, const char *dest_dir) {
    struct dirent *entry;
    struct stat statbuf;
    char src_path[PATH_MAX];
    char dest_path[PATH_MAX];

    DIR *dir = opendir(src_dir);
    if (dir == NULL) {
        perror("Failed to open source directory");
        return;
    }

    if (mkdir(dest_dir, 0755) == -1 && errno != EEXIST) {
        perror("Failed to create destination directory");
        closedir(dir);
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(src_path, sizeof(src_path), "%s/%s", src_dir, entry->d_name);
        snprintf(dest_path, sizeof(dest_path), "%s/%s", dest_dir,
                 entry->d_name);

        if (stat(src_path, &statbuf) == -1) {
            perror("Failed to get file status");
            continue;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            copy_directory(src_path, dest_path);
        } else if (S_ISREG(statbuf.st_mode)) {
            copy_file(src_path, dest_path);
        }
    }

    closedir(dir);
}

void copy_all_files() { copy_directory(SOURCE_DIR, "."); }