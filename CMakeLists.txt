# CMakeLists files in this project can
# refer to the root source directory of the project as ${HELLO_SOURCE_DIR} and
# to the root binary directory of the project as ${HELLO_BINARY_DIR}.
cmake_minimum_required (VERSION 3.12.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

#SET(CMAKE_BUILD_TYPE "Release")
SET(CMAKE_BUILD_TYPE "RelWithDebInfo")

SET(PROJECT_NAME "spmaker") 
PROJECT(${PROJECT_NAME} LANGUAGES CXX) 

SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall -03 -flto -march=native -mute=native")
SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall")

cmake_policy(SET CMP0086 NEW)   # Install CODE|SCRIPT allow the use of generator expressions.
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_STATIC_RUNTIME ON)

if(WIN32)
    message(STATUS "Building for Windows OS")
    SET(JEMALLOC_ROOT_DIR "D:/OPENSOURCES/vcpkg/packages/jemalloc_x86-windows")

    SET(JSON_ROOT D:/LIBRARIES/jsoncpp CACHE STRING "")
    SET(G3LOG_ROOT D:/LIBRARIES/g3log CACHE STRING "")
    SET(CPR_ROOT D:/LIBRARIES/cpr CACHE STRING "")
    SET(ONETBB_ROOT D:/LIBRARIES/onetbb CACHE STRING "")
    SET(BOOST_ROOT D:/OPENSOURCES/vcpkg/installed/x64-windows CACHE STRING "")
    SET(OPENSSL_ROOT D:/OPENSOURCES/vcpkg/installed/x64-windows CACHE STRING "")

elseif(UNIX)
    add_definitions(-DUUID_SYSTEM_GENERATOR)

    SET(JSON_ROOT /usr/local/jsoncpp CACHE STRING "")
    SET(G3LOG_ROOT /usr/local/g3log CACHE STRING "")
    SET(CPR_ROOT /usr/local/cpr CACHE STRING "")
    SET(ONETBB_ROOT /usr/local/onetbb CACHE STRING "")
    SET(BOOST_ROOT /usr/local/boost CACHE STRING "")
    SET(OPENSSL_ROOT /usr/local/openssl CACHE STRING "")
endif()

# build with jemalloc
add_definitions(-DWITH_JEMALLOC)

# build with jemalloc
add_definitions(-DWITH_PERFORMANCE)

# create install directories
SET(BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build CACHE STRING "")
install(DIRECTORY DESTINATION ${BUILD_DIR})
install(DIRECTORY DESTINATION ${BUILD_DIR}/bin)
install(DIRECTORY DESTINATION ${BUILD_DIR}/modules)

# Recurse into the subdirectories. This does not actually
# cause another cmake executable to run. The same process will walk through
# the project's entire directory structure.

add_subdirectory (app)
add_subdirectory (connectors)
