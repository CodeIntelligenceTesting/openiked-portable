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