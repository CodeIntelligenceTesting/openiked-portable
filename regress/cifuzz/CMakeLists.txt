project(CIFuzzTargets)

add_library(CIFuzzTestHelpers)
target_sources(CIFuzzTestHelpers PRIVATE ca.c fuzzdataprovider.c iked_env.c)
#
# Mimic vroute branching from iked subproject.
# Platform test results provided by the top level CMakeLists.txt
#
if(HAVE_VROUTE)
	target_sources(CIFuzzTestHelpers PRIVATE vroute_cleanup_leaked_sockets.c)
endif()
if(HAVE_VROUTE_NETLINK)
	target_sources(CIFuzzTestHelpers PRIVATE vroute_cleanup_leaked_sockets-netlink.c)
endif()
target_link_libraries(CIFuzzTestHelpers iked-shared compat OpenSSL::SSL OpenSSL::Crypto libevent::core)
target_compile_options(CIFuzzTestHelpers PUBLIC -fsanitize=fuzzer -fsanitize=address)
target_link_options(CIFuzzTestHelpers PUBLIC -fsanitize=fuzzer -fsanitize=address)

AddFuzzTarget(
    TARGET_NAME
        ikev2_dispatch_cert
    SOURCES
        ikev2_dispatch_cert.c
    DEPENDENCIES
        CIFuzzTestHelpers
        iked-shared
        compat
)

AddFuzzTarget(
    TARGET_NAME
        ca_dispatch_ikev2
    SOURCES
        ca_dispatch_ikev2.c
    DEPENDENCIES
        CIFuzzTestHelpers
        iked-shared
        compat
)

AddFuzzTarget(
    TARGET_NAME
        parse_config
    SOURCES
        parse_config.c
    DEPENDENCIES
        CIFuzzTestHelpers
        iked-shared
        compat
)

AddFuzzTarget(
    TARGET_NAME
        vroute_getaddr
    SOURCES
        vroute_getaddr.c
    DEPENDENCIES
        CIFuzzTestHelpers
        iked-shared
        compat
)

# these are just for diagnostics in case the fuzzers refuse to load the legacy ciphersuite
add_test(NAME OpenSSLProvidersDefault COMMAND ${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/tools/openssl/openssl list -providers -verbose)
set_property(TEST OpenSSLProvidersDefault PROPERTY ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}$<$<CONFIG:Debug>:/debug>/bin")
set_property(TEST OpenSSLProvidersDefault PROPERTY ENVIRONMENT_MODIFICATION "LD_LIBRARY_PATH=path_list_prepend:${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}$<$<CONFIG:Debug>:/debug>/lib")

add_test(NAME OpenSSLProvidersCustomized COMMAND ${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/tools/openssl/openssl list -providers -verbose)
set_property(TEST OpenSSLProvidersCustomized PROPERTY ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}$<$<CONFIG:Debug>:/debug>/bin")
set_property(TEST OpenSSLProvidersCustomized PROPERTY ENVIRONMENT_MODIFICATION "LD_LIBRARY_PATH=path_list_prepend:${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}$<$<CONFIG:Debug>:/debug>/lib")
set_property(TEST OpenSSLProvidersCustomized APPEND PROPERTY ENVIRONMENT_MODIFICATION "OPENSSL_CONF=set:${CMAKE_CURRENT_SOURCE_DIR}/openssl.cnf")
