include_guard()

function(AddFuzzTarget)
	set(options FUZZER_NO_MAIN)
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

    if (NOT params_FUZZER_NO_MAIN)
        target_link_options(${params_TARGET_NAME} PRIVATE -fsanitize=fuzzer)
    endif ()
endfunction(AddFuzzTarget)
