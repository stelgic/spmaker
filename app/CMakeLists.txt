# Build executable called "craftor" that is built from the source files
SET(TARGET "spmaker") 
PROJECT(${TARGET} LANGUAGES CXX) 

# project include directories
if(UNIX)
    SET (INCLUDE_DIRS
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/datamodels
        ${CMAKE_SOURCE_DIR}/third_party
        ${CMAKE_SOURCE_DIR}/third_party/stduuid
        ${CMAKE_SOURCE_DIR}/third_party/stduuid/include
        ${JSON_ROOT}/include
        ${OPENSSL_ROOT}/include
        ${G3LOG_ROOT}/include
        ${ONETBB_ROOT}/include
        ${BOOST_ROOT}/include
        ${CPR_ROOT}/include
    )

    # external dependency libraries directories
    SET(LIBRARY_DIRS
        ${BOOST_ROOT}/lib
        ${OPENSSL_ROOT}/lib
        ${CPR_ROOT}/lib
        ${CURL_ROOT}/lib
        ${JSON_ROOT}/lib64
        ${G3LOG_ROOT}/lib64
        ${ONETBB_ROOT}/lib64
    )

    # add link libraries
    SET(LIBS 
        m boost_system boost_iostreams boost_program_options 
        stdc++ g3log ssl crypto cpr pthread jsoncpp dl uuid
    )

    # external dependency libraries directories
    SET(BIN_DIRS
        ${JSON_ROOT}/lib64
        ${G3LOG_ROOT}/lib64
    )

elseif(WIN32)
    # Add win 32 includes
    SET (INCLUDE_DIRS
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/datamodels
        ${CMAKE_SOURCE_DIR}/third_party
        ${CMAKE_SOURCE_DIR}/third_party/stduuid
        ${CMAKE_SOURCE_DIR}/third_party/stduuid/include
        ${OPENSSL_ROOT}/openssl/include
        ${BOOST_ROOT}/boost/include
        ${JSON_ROOT}/include
        ${G3LOG_ROOT}/include
        ${ONETBB_ROOT}/include
        ${CPR_ROOT}/include
    )

    # external dependency libraries directories
    SET(LIBRARY_DIRS
        ${BOOST_ROOT}/lib
        ${OPENSSL_ROOT}/lib
        ${CPR_ROOT}/lib
        ${JSON_ROOT}/lib
        ${G3LOG_ROOT}/lib
        ${ONETBB_ROOT}/lib64
    )

    # add link libraries
    SET(LIBS 
        g3log boost_system-vc140-mt boost_program_options-vc140-mt
        boost_iostreams-vc140-mt libssl libcrypto jsoncpp cpr
    )

    SET(BIN_DIRS
        ${BOOST_ROOT}/bin
        ${OPENSSL_ROOT}/bin
        ${CPR_ROOT}/bin
        ${JSON_ROOT}/bin
        ${G3LOG_ROOT}/bin
    )

endif()

# find jmalloc package
if(WITH_JEMALLOC)
    find_package(JeMalloc REQUIRED)
    add_definitions(-DROCKSDB_JEMALLOC)
    include_directories(${JEMALLOC_INCLUDE_DIR})

    list(APPEND INCLUDE_DIRS ${JEMALLOC_INCLUDE_DIR})
    list(APPEND LIBRARY_DIRS ${JEMALLOC_LIBRARY_DIR})
    list(APPEND LIBS ${JEMALLOC_LIBRARIES})
endif()

include_directories(${INCLUDE_DIRS})
link_directories(${LIBRARY_DIRS})

file(GLOB TARGET_SRC
    ${CMAKE_SOURCE_DIR}/public/IExchange.h
    ${CMAKE_SOURCE_DIR}/public/Utils.h
    ${CMAKE_SOURCE_DIR}/public/Utils.cpp
    ${CMAKE_SOURCE_DIR}/datamodels/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/${name}/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/${name}/*.cpp
)

# Add executable called "craftor" that is built from the source files
add_executable(${TARGET} ${TARGET_SRC})

# Link the executable to the library.
target_link_libraries (${TARGET} PRIVATE ${LIBS})

set(EXECUTABLE_DIR ${BUILD_DIR}/bin)
install(DIRECTORY DESTINATION ${EXECUTABLE_DIR})
install(TARGETS ${TARGET} RUNTIME DESTINATION ${EXECUTABLE_DIR})

set(SRC_CONFIG_DIR ${CMAKE_CURRENT_SOURCE_DIR}/configs)
set(CONFIG_DIR ${BUILD_DIR}/configs)
install(DIRECTORY ${SRC_CONFIG_DIR}/ DESTINATION ${CONFIG_DIR})

set(MODULE_DIR ${BUILD_DIR}/modules)
install(DIRECTORY DESTINATION ${MODULE_DIR})

if(UNIX)
    set(TARGET_FILE ${EXECUTABLE_DIR}/${TARGET})
    file(GLOB TARGET_MODULES
        ${MODULE_DIR}/*.so
    )
    list(APPEND TARGET_MODULES ${TARGET_FILE})
elseif(WIN32)
    set(TARGET_FILE ${EXECUTABLE_DIR}/${TARGET}.exe)
    file(GLOB TARGET_MODULES
        ${MODULE_DIR}/*.dll
    )
    list(APPEND TARGET_MODULES ${TARGET_FILE})
endif()

# Transfer the value of ${MY_DEPENDENCY_PATHS} into the install script
set(MY_DEPENDENCY_PATHS ${BIN_DIRS})
install(CODE "set(MY_DEPENDENCY_PATHS \"${MY_DEPENDENCY_PATHS}\")")
install(CODE "set(EXECUTABLE_DIR \"${EXECUTABLE_DIR}\")")
install(CODE "set(TARGET_FILE \"${TARGET_FILE}\")")
install(CODE "set(TARGET_MODULES \"${TARGET_MODULES}\")")

install(CODE "
    file(GET_RUNTIME_DEPENDENCIES
        EXECUTABLES ${TARGET_MODULES} 
        CONFLICTING_DEPENDENCIES_PREFIX _c_deps
        RESOLVED_DEPENDENCIES_VAR _r_deps
        UNRESOLVED_DEPENDENCIES_VAR _u_deps
        DIRECTORIES ${MY_DEPENDENCY_PATHS}
    )"
)

install(CODE [[
        foreach(dep ${_r_deps})
            foreach(bdir ${MY_DEPENDENCY_PATHS})
                string(FIND ${dep} ${bdir} res)
                if (NOT ${res} EQUAL -1)
                    file(INSTALL DESTINATION ${EXECUTABLE_DIR} FOLLOW_SYMLINK_CHAIN FILES "${dep}")
                endif()
            endforeach()
        endforeach()
    ]]
)
