find_package(LLVM REQUIRED CONFIG)

file(GLOB_RECURSE CLANG_RT_LIBS "${LLVM_INSTALL_PREFIX}/*/libclang_rt.*.a")
set(clang_rt_paths)
foreach(clang_rt_lib IN LISTS CLANG_RT_LIBS)
  get_filename_component(dir "${clang_rt_lib}" DIRECTORY)
  list(APPEND clang_rt_paths ${dir})
endforeach()
list(SORT clang_rt_paths)
list(REMOVE_DUPLICATES clang_rt_paths)
message(STATUS "libclang_rt in ${clang_rt_paths}")

find_library(clang_rt_fuzzer_lib
  NAMES
    libclang_rt.fuzzer.a
    libclang_rt.fuzzer-${CMAKE_SYSTEM_PROCESSOR}.a
  PATHS
    ${clang_rt_paths}
  REQUIRED
)

add_library(unofficial::clang_rt::fuzzer UNKNOWN IMPORTED)
set_target_properties(unofficial::clang_rt::fuzzer PROPERTIES IMPORTED_LOCATION "${clang_rt_fuzzer_lib}")

include(FeatureSummary)
set_package_properties(unofficial::clang_rt::fuzzer PROPERTIES
  DESCRIPTION "libfuzzer runtime libraries"
)
