# CMakeLists.txt  –  libecho
#
# Builds a shared/static helper library that:
#   - reads config.xml (TinyXML)
#   - imports a .proto file at runtime (Protobuf reflection API)
#   - exposes a plain-C API for use by the Wireshark dissector plugin
#
# SPDX-License-Identifier: GPL-2.0-or-later

cmake_minimum_required(VERSION 3.16)
project(libecho CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Protobuf REQUIRED)

set(LIBECHO_SRC
    libecho/libecho.cpp
    libecho/tinyxml.cpp
    libecho/tinyxmlerror.cpp
    libecho/tinyxmlparser.cpp
    libecho/tinystr.cpp
)

add_library(echo STATIC ${LIBECHO_SRC})

target_include_directories(echo PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/libecho
    ${Protobuf_INCLUDE_DIRS}
)

target_link_libraries(echo PUBLIC
    ${Protobuf_LIBRARIES}
)

# Optional: build the test executable
option(BUILD_TESTS "Build libecho test binary" OFF)
if(BUILD_TESTS)
    add_executable(echo_test test/test.cpp)
    target_link_libraries(echo_test PRIVATE echo)
endif()
