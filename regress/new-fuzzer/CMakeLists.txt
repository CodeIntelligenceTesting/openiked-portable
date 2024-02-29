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

function(AddFuzzTarget)
	set(options)
	set(oneValueArgs TARGET_NAME)
	set(multiValueArgs SOURCES DEPENDENCIES)

	cmake_parse_arguments(params "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    message(STATUS "Fuzz Target ${params_TARGET_NAME}")

    if(CIFUZZ_TESTING)
        add_fuzz_test(${params_TARGET_NAME} ${params_SOURCES})
        target_link_libraries(${params_TARGET_NAME} PRIVATE ${params_DEPENDENCIES})
    else(CIFUZZ_TESTING)
        add_executable(${params_TARGET_NAME})
        target_sources(${params_TARGET_NAME} PRIVATE ${params_SOURCES})
        target_link_libraries(${params_TARGET_NAME} PRIVATE ${params_DEPENDENCIES})
        add_test(NAME ${params_TARGET_NAME}/fuzz COMMAND ${params_TARGET_NAME} -max_total_time=10 COMMAND_EXPAND_LISTS)
        set_property(TEST ${params_TARGET_NAME}/fuzz APPEND PROPERTY ENVIRONMENT_MODIFICATION "OPENSSL_CONF=set:${CMAKE_CURRENT_SOURCE_DIR}/openssl.cnf")

        if(COVERAGE_REPORT)
            set(llvmProfFile "$<TARGET_FILE:${params_TARGET_NAME}>.profraw.${PRESET_NAME}")
	        set(llvmProfData "$<TARGET_FILE:${params_TARGET_NAME}>.profdata.${PRESET_NAME}")
            set_property(TEST ${params_TARGET_NAME}/fuzz APPEND PROPERTY ENVIRONMENT_MODIFICATION "LLVM_PROFILE_FILE=set:${llvmProfFile}")
            set_tests_properties(${params_TARGET_NAME}/fuzz PROPERTIES FIXTURES_REQUIRED ${params_TARGET_NAME}Fixture)

            add_test(NAME ${params_TARGET_NAME}/mergeCoverageData    COMMAND ${LLVM_PROFDATA_COMMAND} merge -sparse "${llvmProfFile}" -o "${llvmProfData}")
		    add_test(NAME ${params_TARGET_NAME}/generateCoverageHtml COMMAND ${LLVM_COV_COMMAND} show "$<TARGET_FILE:${params_TARGET_NAME}>" "-instr-profile=${llvmProfData}" --output-dir "${CMAKE_CURRENT_BINARY_DIR}/coverage/${params_TARGET_NAME}/${PRESET_NAME}" "--format=html")

            set_tests_properties(${params_TARGET_NAME}/mergeCoverageData PROPERTIES FIXTURES_CLEANUP ${params_TARGET_NAME}Fixture)
            set_tests_properties(${params_TARGET_NAME}/generateCoverageHtml PROPERTIES FIXTURES_CLEANUP ${params_TARGET_NAME}Fixture)

		    set_tests_properties(${params_TARGET_NAME}/generateCoverageHtml  PROPERTIES DEPENDS ${params_TARGET_NAME}/mergeCoverageData)
        endif(COVERAGE_REPORT)
    endif(CIFUZZ_TESTING)
endfunction(AddFuzzTarget)

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
