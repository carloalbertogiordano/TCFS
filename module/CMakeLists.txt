cmake_minimum_required(VERSION 3.0)

project(TCFS)

set(CMAKE_C_FLAGS "-Wall -Wextra -std=c99")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/../cmake/")

find_package(Fuse REQUIRED)

# Add dependency dir
add_subdirectory(crypt-utils)

add_definitions(${FUSE_DEFINITIONS})
include_directories(${FUSE_INCLUDE_DIRS})
add_executable(tcfs tcfs.c)

# Link files
target_sources(tcfs PRIVATE crypt-utils/crypt-utils.c)

target_link_libraries(tcfs ${FUSE_LIBRARIES} crypt-utils)

install(TARGETS tcfs DESTINATION bin)
