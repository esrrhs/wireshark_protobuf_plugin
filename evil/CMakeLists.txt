# CMakeLists.txt  –  Wireshark dissector plugin: evil
#
# Wireshark - Network traffic analyzer
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Compatible with Wireshark 3.x / 4.x CMake build system.

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(evil 1 0 0 0)

set(DISSECTOR_SRC
    packet-evil.c
)

set(PLUGIN_FILES
    plugin.c
    ${DISSECTOR_SRC}
)

set(CLEAN_FILES
    ${PLUGIN_FILES}
)

if(WERROR_COMMON_FLAGS)
    set_source_files_properties(
        ${CLEAN_FILES}
        PROPERTIES
        COMPILE_FLAGS ${WERROR_COMMON_FLAGS}
    )
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Link against libecho (protobuf helper) and protobuf
find_package(Protobuf REQUIRED)

register_plugin_files(plugin.c
    plugin
    ${DISSECTOR_SRC}
)

add_plugin_library(evil epan)

target_include_directories(evil PRIVATE
    ${Protobuf_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/../libecho/libecho
)

target_link_libraries(evil PRIVATE
    ${Protobuf_LIBRARIES}
    echo      # libecho – built separately (see libecho/)
)

install(TARGETS evil
    LIBRARY DESTINATION
        ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}/epan
        NAMELINK_SKIP
    RUNTIME DESTINATION
        ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}/epan
    ARCHIVE DESTINATION
        ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}/epan
)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
    NAME
      evil
    SWITCHES
      -g abort -g termoutput -build
    SOURCES
      ${DISSECTOR_SRC}
      ${DISSECTOR_HEADERS}
)
