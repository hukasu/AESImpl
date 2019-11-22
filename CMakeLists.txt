cmake_minimum_required(VERSION 3.8.2)

project('AES')

option(BUILD_COMMAND_LINE_TOOL "Should the command line tool be build?" OFF)

add_library(
	aes_lib
	src/aes_lib.cpp
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