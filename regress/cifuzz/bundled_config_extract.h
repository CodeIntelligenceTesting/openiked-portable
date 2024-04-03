#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * extract bundled config files to the file system.
 */
int cifuzz_bundled_config_extract(const char *prefix);

#ifdef __cplusplus
}
#endif