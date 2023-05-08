# macro to generate cmake for each subfolder

macro( add_connector_module name INSTALL_DEPS)
    SET(CONNECTOR_TARGET ${name}) 
    PROJECT(${CONNECTOR_TARGET} LANGUAGES CXX) 

    # build shared module
    add_definitions(-DBUILD_SHARED_LIBS=ON)

    # project include directories
    if(UNIX) 
        message(STATUS ${CPR_ROOT})       
        SET (INCLUDE_DIRS
            ${CMAKE_SOURCE_DIR}
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_SOURCE_DIR}/third_party
            ${CMAKE_SOURCE_DIR}/third_party/stduuid
            ${CMAKE_SOURCE_DIR}/third_party/stduuid/include
            ${JSON_ROOT}/include
            ${OPENSSL_ROOT}/include
            ${G3LOG_ROOT}/include
            ${ONETBB_ROOT}/include
            ${BOOST_ROOT}/include
            ${CPR_ROOT}/include
            ${CURL_ROOT}/include
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
            ${CURL_ROOT}/lib
        )

        # add link libraries
        SET(LIBS 
            m boost_system boost_iostreams boost_program_options 
            stdc++ g3log ssl crypto cpr pthread jsoncpp dl uuid
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
            ${JSON_ROOT}/include
            ${OPENSSL_ROOT}/include
            ${G3LOG_ROOT}/include
            ${ONETBB_ROOT}/include
            ${BOOST_ROOT}/include
            ${CPR_ROOT}/include
            ${CURL_ROOT}/include
        )

        # external dependency libraries directories
        SET(LIBRARY_DIRS
            ${BOOST_ROOT}/lib
            ${OPENSSL_ROOT}/lib
            ${CPR_ROOT}/lib
            ${CURL_ROOT}/lib
            ${JSON_ROOT}/lib
            ${G3LOG_ROOT}/lib
            ${ONETBB_ROOT}/lib64
            ${CURL_ROOT}/lib
        )

        # add link libraries
        SET(LIBS 
            boost_system-vc140-mt boost_iostreams-vc140-mt
            boost_program_options-vc140-mt g3log libssl libcrypto cpr jsoncpp
        )

        SET(BIN_DIRS
            ${JSON_ROOT}/lib
            ${G3LOG_ROOT}/lib
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
        ${CMAKE_SOURCE_DIR}/public/ConnHandler.h
        ${CMAKE_SOURCE_DIR}/public/IExchange.h
        ${CMAKE_SOURCE_DIR}/public/Utils.h
        ${CMAKE_SOURCE_DIR}/public/AuthUtils.h
        ${CMAKE_SOURCE_DIR}/public/datamodels/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/${name}/*.h
        ${CMAKE_CURRENT_SOURCE_DIR}/${name}/*.cpp
    )

    # Add executable called "craftor" that is built from the source files
    add_library(${CONNECTOR_TARGET} SHARED ${TARGET_SRC})

    # Link the executable to the library.
    target_link_libraries (${CONNECTOR_TARGET} PUBLIC ${LIBS})

    set(CONNECTOR_LIB_DIR ${BUILD_DIR}/modules)
    # install(DIRECTORY DESTINATION ${CONNECTOR_LIB_DIR})
    if(UNIX)
        install(TARGETS ${CONNECTOR_TARGET} LIBRARY DESTINATION ${CONNECTOR_LIB_DIR})
    elseif(WIN32)
        install(TARGETS ${CONNECTOR_TARGET} RUNTIME DESTINATION ${CONNECTOR_LIB_DIR})
    endif()
endmacro()
