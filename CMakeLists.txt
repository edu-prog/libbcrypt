# ##################################################################################
#
# Copyright (c) 2014, webvariants GmbH, http://www.webvariants.de
#
# This file is released under the terms of the MIT license. You can find the
# complete text in the attached LICENSE file or online at:
#
# http://www.opensource.org/licenses/mit-license.php
#
# @author: Tino Rusch (tino.rusch@webvariants.de)
#
# ##################################################################################

cmake_minimum_required(VERSION 3.16)

project(bcrypt)

enable_language(ASM)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_ASM_FLAGS "${CXXFLAGS} -x assembler-with-cpp")

add_library(
	${PROJECT_NAME}
	${CMAKE_CURRENT_SOURCE_DIR}/src/bcrypt.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_blowfish.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/crypt_gensalt.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/wrapper.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/x86.S
)

target_include_directories(${PROJECT_NAME} INTERFACE include)
target_include_directories(${PROJECT_NAME} INTERFACE src)

include(GNUInstallDirs)

install(TARGETS ${PROJECT_NAME}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bcrypt)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
	FILES_MATCHING
	PATTERN "*.h"
)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	if(SANITIZERS)
		set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address,undefined")
	endif()

	if(TESTING)
		enable_testing()
		add_subdirectory(tests)
	endif()

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -Wall -Werror")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
	if(BENCHMARKS)
		# add_subdirectory(benchmark)
	endif()

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
endif()