project(CIFuzzTargets)

add_library(CIFuzzTestHelpers)
target_sources(CIFuzzTestHelpers PRIVATE
    ca.c
    fuzzdataprovider.c
    iked_env.c
)
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

file(READ bundled_config.tar.gz content HEX)
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
configure_file(bundled_config_embedded_blob.c.in bundled_config_embedded_blob.c @ONLY)

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
    ${CMAKE_CURRENT_BINARY_DIR}/bundled_config_embedded_blob.c
    bundled_config_prefix.c
    bundled_config_extract.c
)
target_compile_definitions(CIFuzzTestHelpers PRIVATE CMAKE_INSTALL_SYSCONFDIR="${CMAKE_INSTALL_SYSCONFDIR}")
target_include_directories(CIFuzzTestHelpers PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(CIFuzzTestHelpers PUBLIC LibArchive::LibArchive ZLIB::ZLIB BZip2::BZip2)

AddFuzzTarget(
    TARGET_NAME
        ca_dispatch_control_fuzzer
    SOURCES
        ca_dispatch_control_fuzzer.c
    DEPENDENCIES
        CIFuzzTestHelpers
        iked-shared
        compat
)

AddFuzzTarget(
    TARGET_NAME
        ca_dispatch_ikev2_fuzzer
    SOURCES
        ca_dispatch_ikev2_fuzzer.c
    DEPENDENCIES
        CIFuzzTestHelpers
        iked-shared
        compat
)

AddFuzzTarget(
    TARGET_NAME
        ikev2_dispatch_cert_fuzzer
    SOURCES
        ikev2_dispatch_cert_fuzzer.c
    DEPENDENCIES
        CIFuzzTestHelpers
        iked-shared
        compat
)

AddFuzzTarget(
    TARGET_NAME
        ikev2_dispatch_control_fuzzer
    SOURCES
        ikev2_dispatch_control_fuzzer.c
    DEPENDENCIES
        CIFuzzTestHelpers
        iked-shared
        compat
)

AddFuzzTarget(
    TARGET_NAME
        ikev2_dispatch_parent_fuzzer
    SOURCES
        ikev2_dispatch_parent_fuzzer.c
    DEPENDENCIES
        CIFuzzTestHelpers
        iked-shared
        compat
)

AddFuzzTarget(
    TARGET_NAME
        oscp_connect_fuzzer
    SOURCES
        oscp_connect_fuzzer.c
    DEPENDENCIES
        CIFuzzTestHelpers
        iked-shared
        compat
)

AddFuzzTarget(
    TARGET_NAME
        parse_config_fuzzer
    SOURCES
        parse_config_fuzzer.c
    DEPENDENCIES
        CIFuzzTestHelpers
        iked-shared
        compat
)

AddFuzzTarget(
    TARGET_NAME
        vroute_getaddr_fuzzer
    SOURCES
        vroute_getaddr_fuzzer.c
    DEPENDENCIES
        CIFuzzTestHelpers
        iked-shared
        compat
)

find_package(nlohmann_json 3.2.0 REQUIRED)
find_package(ClangRTFuzzer REQUIRED)

add_library(CIFuzzArgumentRediction)
target_sources(CIFuzzArgumentRediction PRIVATE injected_fuzzer_arguments.cpp)
target_link_libraries(CIFuzzArgumentRediction PRIVATE nlohmann_json::nlohmann_json)

add_executable(ikectl_fuzzer_runner)
target_sources(ikectl_fuzzer_runner PRIVATE injected_fuzzer_runner.cpp)
target_link_libraries(ikectl_fuzzer_runner PRIVATE CIFuzzArgumentRediction)

AddFuzzTarget(
    TARGET_NAME
        ikectl_fuzzer
    SOURCES
        ikectl_fuzzer.cpp
        ikectl_fuzzer_impl.cpp
        injected_fuzzer_impl.c
        ${openiked_SOURCE_DIR}/iked/iked.c
    DEPENDENCIES
        CIFuzzTestHelpers
        CIFuzzArgumentRediction
        iked-shared
        compat
        unofficial::clang_rt::fuzzer
    FUZZER_NO_MAIN
)
