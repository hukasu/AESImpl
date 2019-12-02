cmake_minimum_required(VERSION 3.8.2)

project('AES')

option(BUILD_COMMAND_LINE_TOOL "Should the command line tool be build?" OFF)
option(BUILD_TESTS "Should the tests be build?" OFF)

add_library(
	aes_lib
	src/aes_lib.cpp
)
target_compile_features(
	aes_lib
	PUBLIC cxx_std_17
)
target_include_directories(
	aes_lib
	INTERFACE src
)

if (BUILD_COMMAND_LINE_TOOL)
	add_executable(
		aes
		src/main.cpp
	)
	target_link_libraries(
		aes
		PUBLIC aes_lib
	)
endif()

if (BUILD_TESTS)
	enable_testing()
	add_executable(aes_test_vectors test/aes_test_vectors.cpp)
	target_link_libraries(
		aes_test_vectors
		PUBLIC aes_lib
	)

	add_test(
		NAME test_vector_1 
		COMMAND aes_test_vectors 00112233445566778899aabbccddeeff 69c4e0d86a7b0430d8cdb78070b4c55a 000102030405060708090a0b0c0d0e0f
	)
endif()