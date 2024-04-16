#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/***
 * @brief extract a tar file to the file system
 * @arg prefix the to extract to
 * @arg blob the tar file, in memory
 * @arg blob_size the length of @ref blob
 * @return 0 on succes.
 * @remark extracting tarfiles containing links was not tested and probably doesn't work
 */
int cifuzz_bundled_config_extract(const char *prefix, const uint8_t *blob, size_t blob_size);

#ifdef __cplusplus
}
#endif