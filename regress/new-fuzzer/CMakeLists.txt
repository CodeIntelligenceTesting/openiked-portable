add_executable(NewFuzzTarget)

target_sources(NewFuzzTarget PRIVATE main.c)

target_compile_options(NewFuzzTarget PRIVATE -fsanitize=fuzzer)
target_link_options(NewFuzzTarget PRIVATE -fsanitize=fuzzer)

target_link_libraries(NewFuzzTarget PRIVATE iked-shared compat)