#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/***
 * @brief embedded binary blob
 * @returns pointer to embedded blob
 * @remark
 *   to manually generate the blob, run something like
 *   @code{.sh}
 *     cd /etc
 *     tar czf - iked.conf iked | hd -ve '1/1 "0x%.2x," ' ; echo '' ;
 *   @endcode
 *   where @c /etc is the value of CMAKE_INSTALL_SYSCONFDIR,
 *   which is manually set in openiked's top level CMakeLists.txt
 */
const uint8_t *cifuzz_bundled_config_embedded_blob();

/***
 * @brief embedded binary blob size
 * @returns length of memory pointed at by @c cifuzz_bundled_config_embedded_blob
 * @remark
 *   to manually generate the blob size, run something like
 *   @code{.sh}
 *     cd /etc
 *     tar czf - iked.conf iked | wc -c
 *   @endcode
 *   where @c /etc is the value of CMAKE_INSTALL_SYSCONFDIR,
 *   which is manually set in openiked's top level CMakeLists.txt
 */
size_t cifuzz_bundled_config_embedded_blob_size();

#ifdef __cplusplus
}
#endif