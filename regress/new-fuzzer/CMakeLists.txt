project(NewFuzzers)

add_library(CIFuzzTestHelpers)
target_sources(CIFuzzTestHelpers PRIVATE fuzzdataprovider.c iked_env.c)
target_link_libraries(CIFuzzTestHelpers iked-shared compat)
target_compile_options(CIFuzzTestHelpers PUBLIC -fsanitize=fuzzer -fsanitize=address)
target_link_options(CIFuzzTestHelpers PUBLIC -fsanitize=fuzzer -fsanitize=address)

add_executable(NewFuzzTarget)
target_sources(NewFuzzTarget PRIVATE main.c)
target_link_libraries(NewFuzzTarget PRIVATE iked-shared compat CIFuzzTestHelpers)


add_executable(vroute_getaddr)
target_sources(vroute_getaddr PRIVATE vroute_getaddr.c)
target_link_libraries(vroute_getaddr PRIVATE iked-shared compat CIFuzzTestHelpers)
add_test(NAME vroute_getaddr COMMAND vroute_getaddr -max_total_time=10 COMMAND_EXPAND_LISTS)
set_property(TEST vroute_getaddr APPEND PROPERTY ENVIRONMENT_MODIFICATION "OPENSSL_CONF=set:${CMAKE_CURRENT_SOURCE_DIR}/openssl.cnf")

add_test(NAME OpenSSLProvidersDefault COMMAND ${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/tools/openssl/openssl list -providers -verbose)
set_property(TEST OpenSSLProvidersDefault PROPERTY ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}$<$<CONFIG:Debug>:/debug>/bin")
set_property(TEST OpenSSLProvidersDefault PROPERTY ENVIRONMENT_MODIFICATION "LD_LIBRARY_PATH=path_list_prepend:${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}$<$<CONFIG:Debug>:/debug>/lib")

add_test(NAME OpenSSLProvidersCustomized COMMAND ${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/tools/openssl/openssl list -providers -verbose)
set_property(TEST OpenSSLProvidersCustomized PROPERTY ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}$<$<CONFIG:Debug>:/debug>/bin")
set_property(TEST OpenSSLProvidersCustomized PROPERTY ENVIRONMENT_MODIFICATION "LD_LIBRARY_PATH=path_list_prepend:${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}$<$<CONFIG:Debug>:/debug>/lib")
set_property(TEST OpenSSLProvidersCustomized APPEND PROPERTY ENVIRONMENT_MODIFICATION "OPENSSL_CONF=set:${CMAKE_CURRENT_SOURCE_DIR}/openssl.cnf")
