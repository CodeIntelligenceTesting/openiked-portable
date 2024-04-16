project(CIFuzzTargets)

add_library(CIFuzzTestHelpers)
target_sources(CIFuzzTestHelpers PRIVATE
    ca.c
    fuzzdataprovider.c
    cifuzz_create_iked_env_aux.c
    cifuzz_create_iked_env.c
    cifuzz_destroy_iked_env_aux.c
    cifuzz_destroy_iked_env.c
)
#
# Mimic vroute branching from iked subproject.
# Platform test results provided by the top level CMakeLists.txt
#
if(HAVE_VROUTE)
	target_sources(CIFuzzTestHelpers PRIVATE cifuzz_vroute_cleanup_leaked_sockets.c)
endif()
if(HAVE_VROUTE_NETLINK)
	target_sources(CIFuzzTestHelpers PRIVATE cifuzz_vroute_cleanup_leaked_sockets-netlink.c)
endif()
target_link_libraries(CIFuzzTestHelpers PUBLIC iked-shared compat OpenSSL::SSL OpenSSL::Crypto libevent::core)
target_compile_options(CIFuzzTestHelpers PUBLIC -fsanitize=fuzzer-no-link -fsanitize=address)
target_link_options(CIFuzzTestHelpers PUBLIC -fsanitize=address)

#
# Helper functions
#
target_sources(CIFuzzTestHelpers PRIVATE
    cifuzz_imsg_clamp_if_larger.c
    cifuzz_imsg_fail_if_smaller.c
)

#
# implicit bundled config file extraction.
#

file(READ cifuzz_bundled_config.tar.gz content HEX)
string(REGEX MATCHALL "([A-Fa-f0-9][A-Fa-f0-9])" SEPARATED_HEX ${content})
set(file_content_as_c_array "")
set(index 0)
foreach (hex IN LISTS SEPARATED_HEX)
	string(APPEND file_content_as_c_array "0x${hex},")
    math(EXPR index "${index}+1")
    if (index GREATER 16)
        string(APPEND file_content_as_c_array "\n    ")
        set(index 0)
    endif ()
endforeach ()
configure_file(cifuzz_bundled_config_embedded_blob.c.in cifuzz_bundled_config_embedded_blob.c @ONLY)

# We need to pass CMAKE_INSTALL_SYSCONFDIR into the source here,
# because the location config files are expected by iked is
# hard-coded but varying depending on the branch taken in
# https://github.com/openiked/openiked-portable/blob/6d5b015f50301ffb1800f36f636b953a714c9e62/CMakeLists.txt#L47
# 
# Also, libarchive seems not to be refrencing its deep-endencies [...]
#
find_package(LibArchive REQUIRED)
find_package(ZLIB REQUIRED) 
find_package(BZip2 REQUIRED)
target_sources(CIFuzzTestHelpers PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}/cifuzz_bundled_config_embedded_blob.c
    cifuzz_bundled_config_prefix.c
    cifuzz_bundled_config_extract.c
)
target_compile_definitions(CIFuzzTestHelpers PRIVATE CMAKE_INSTALL_SYSCONFDIR="${CMAKE_INSTALL_SYSCONFDIR}")
target_include_directories(CIFuzzTestHelpers PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(CIFuzzTestHelpers PUBLIC LibArchive::LibArchive ZLIB::ZLIB BZip2::BZip2)


set(fuzzers
    ca_dispatch_control_fuzzer
    ca_dispatch_ikev2_fuzzer
    ca_dispatch_parent_fuzzer
    ikev2_dispatch_cert_fuzzer
    ikev2_dispatch_control_fuzzer
    ikev2_dispatch_parent_fuzzer
    oscp_connect_fuzzer
    parse_config_fuzzer
    vroute_getaddr_fuzzer
)
foreach(fuzzer IN LISTS fuzzers)
    AddFuzzTarget(TARGET_NAME ${fuzzer} SOURCES ${fuzzer}.c DEPENDENCIES CIFuzzTestHelpers iked-shared compat)
endforeach()
