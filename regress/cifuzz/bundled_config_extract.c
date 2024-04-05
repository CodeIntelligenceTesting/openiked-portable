#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <archive.h>
#include <archive_entry.h>

#include "bundled_config_extract.h"

static int copy_data(struct archive *ar, struct archive *aw);

int cifuzz_bundled_config_extract(const char *prefix, const uint8_t *blob, size_t blob_size)
{        
        struct archive *a;
        struct archive *ext;
        struct archive_entry *entry;
        int flags;
        int r;

        a = archive_read_new();
        ext = archive_write_disk_new();
        flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM /* | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS */;
        archive_write_disk_set_options(ext, flags);
        archive_read_support_format_all(a);
        archive_read_support_filter_all(a);

        r = archive_read_open_memory(a, blob, blob_size);
        assert(r == ARCHIVE_OK);

        for (;;) {
                r = archive_read_next_header(a, &entry);
                if (r == ARCHIVE_EOF)
                        break;
                assert(r == ARCHIVE_OK);
                
                const char *pathname = archive_entry_pathname(entry);
                char *prefixedFilename = (char *)malloc(strlen(prefix) + strlen("/") + strlen(pathname) + sizeof('\0'));
                sprintf(prefixedFilename, "%s/%s", prefix, pathname);
                printf("%s:%d: extracting %s\n", __FILE__, __LINE__, pathname);
                archive_entry_set_pathname_utf8(entry, prefixedFilename);

                r = archive_write_header(ext, entry);
                if (r != ARCHIVE_OK) {
                        printf("%s:%d: archive_write_header(): %s\n", __FILE__, __LINE__, archive_error_string(ext));
                }
                else {
                        r = copy_data(a, ext);
                        assert(r == ARCHIVE_OK);

                        r = archive_write_finish_entry(ext);
                        assert(r == ARCHIVE_OK);
                }
        }
        archive_read_close(a);
        archive_read_free(a);

        archive_write_close(ext);
        archive_write_free(ext);
        
        return (0);
}

int copy_data(struct archive *ar, struct archive *aw)
{
        int r;
        const void *buff;
        size_t size;
#if ARCHIVE_VERSION_NUMBER >= 3000000
        int64_t offset;
#else
        off_t offset;
#endif

        for (;;) {
                r = archive_read_data_block(ar, &buff, &size, &offset);
                if (r == ARCHIVE_EOF)
                        return (ARCHIVE_OK);
                if (r != ARCHIVE_OK)
                        return (r);
                r = archive_write_data_block(aw, buff, size, offset);
                if (r != ARCHIVE_OK) {
                        printf("%s:%d: archive_write_data_block(): %s\n", __FILE__, __LINE__, archive_error_string(aw));
                        return (r);
                }
        }
}
