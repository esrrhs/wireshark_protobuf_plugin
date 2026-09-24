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
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

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

if(TARGET protobuf::libprotobuf)
    set(PROTOBUF_TARGETS protobuf::libprotobuf)
    if(TARGET protobuf::libprotoc)
        list(APPEND PROTOBUF_TARGETS protobuf::libprotoc)
    endif()
else()
    set(PROTOBUF_TARGETS ${Protobuf_LIBRARIES})
    if(Protobuf_PROTOC_LIBRARIES)
        list(APPEND PROTOBUF_TARGETS ${Protobuf_PROTOC_LIBRARIES})
    endif()
endif()

target_link_libraries(echo PUBLIC ${PROTOBUF_TARGETS})

# Optional: build the test executable and enable ctest
option(BUILD_TESTS "Build libecho test binary" ON)
if(BUILD_TESTS)
    enable_testing()
    add_executable(echo_test test/test.cpp)
    target_link_libraries(echo_test PRIVATE echo ${PROTOBUF_TARGETS})
    target_include_directories(echo_test PRIVATE ${Protobuf_INCLUDE_DIRS})

    # Copy test config and test proto to build directory
    add_custom_command(TARGET echo_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/test/config.xml
            $<TARGET_FILE_DIR:echo_test>/config.xml
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/test/test.proto
            $<TARGET_FILE_DIR:echo_test>/test.proto
    )

    add_test(NAME echo_unit_test COMMAND echo_test)
endif()
