project(NewFuzzers)

add_library(FuzzDataProvider fuzzdataprovider.c)
target_compile_options(FuzzDataProvider PUBLIC -fsanitize=fuzzer -fsanitize=address)
target_link_options(FuzzDataProvider PUBLIC -fsanitize=fuzzer -fsanitize=address)

add_executable(NewFuzzTarget)
target_sources(NewFuzzTarget PRIVATE main.c)
target_link_libraries(NewFuzzTarget PRIVATE iked-shared compat FuzzDataProvider)


add_executable(InitIkedEnv)
target_sources(InitIkedEnv PRIVATE init_iked_env.c)
target_link_libraries(InitIkedEnv PRIVATE iked-shared compat FuzzDataProvider)
#add_test(NAME InitIkedEnv COMMAND InitIkedEnv -max_total_time=10 COMMAND_EXPAND_LISTS)
#set_property(TEST InitIkedEnv APPEND PROPERTY ENVIRONMENT_MODIFICATION "OPENSSL_CONF=set:${CMAKE_CURRENT_SOURCE_DIR}/openssl.cnf")

add_test(NAME OpenSSLProvidersDefault COMMAND ${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/tools/openssl/openssl list -providers -verbose)
set_property(TEST OpenSSLProvidersDefault PROPERTY ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}$<$<CONFIG:Debug>:/debug>/bin")
set_property(TEST OpenSSLProvidersDefault PROPERTY ENVIRONMENT_MODIFICATION "LD_LIBRARY_PATH=path_list_prepend:${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}$<$<CONFIG:Debug>:/debug>/lib")

add_test(NAME OpenSSLProvidersCustomized COMMAND ${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/tools/openssl/openssl list -providers -verbose)
set_property(TEST OpenSSLProvidersCustomized PROPERTY ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}$<$<CONFIG:Debug>:/debug>/bin")
set_property(TEST OpenSSLProvidersCustomized PROPERTY ENVIRONMENT_MODIFICATION "LD_LIBRARY_PATH=path_list_prepend:${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}$<$<CONFIG:Debug>:/debug>/lib")
set_property(TEST OpenSSLProvidersCustomized APPEND PROPERTY ENVIRONMENT_MODIFICATION "OPENSSL_CONF=set:${CMAKE_CURRENT_SOURCE_DIR}/openssl.cnf")
