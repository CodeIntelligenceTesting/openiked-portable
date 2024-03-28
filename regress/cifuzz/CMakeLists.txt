project(CIFuzzTargets)

configure_file(iked.conf.in iked.conf COPYONLY)

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
target_compile_options(CIFuzzTestHelpers PUBLIC -fsanitize=fuzzer-no-link -fsanitize=address)
target_link_options(CIFuzzTestHelpers PUBLIC -fsanitize=address)

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
