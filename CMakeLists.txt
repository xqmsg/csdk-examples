cmake_minimum_required(VERSION 3.10)

if (NOT DEFINED sdk)
message(FATAL_ERROR "Path to XQ CSDK library must be defined (-Dsdk=/path/to/library_folder)")
else()
set(XQCSDK_LIB_PATH ${sdk}/libxqc.a)
endif()

if (NOT DEFINED headers)
message(FATAL_ERROR "Path to XQ CSDK headers must be defined (-Dheaders=/path/to/headers)")
else()
set( XQSDK_HEADER_PATH ${headers} )
endif()

# Set the project name.
project( xq-examples )

if (APPLE) 
    set(CMAKE_C_COMPILER /usr/bin/gcc)
    set(CMAKE_CXX_COMPILER /usr/bin/g++)
    set(CMAKE_CXX_STANDARD 11)
    set(CMAKE_OSX_ARCHITECTURES x86_64)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15" CACHE STRING "Minimum OS X deployment version" FORCE)
    set(OPENSSL_ROOT_DIR ${OPENSSL_ROOT_DIR} /usr/local/Cellar/openssl@1.1/1.1.1i/)
    set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libcrypto.dylib CACHE FILEPATH "" FORCE)
    set(OPENSSL_SSL_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libssl.dylib CACHE FILEPATH "" FORCE)
endif()


# Set the output directory.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_BUILD_FILES_DIRECTORY ${CMAKE_BINARY_DIR}/build )

if( UNIX AND NOT APPLE )
set ( CMAKE_PREFIX_PATH /usr/lib/x86_64-linux-gnu/cmake/ )
endif()

# Ensure that openSSL, boost and cpprestsdk exist.
find_package(OpenSSL 1.1 REQUIRED)
find_package(CURL REQUIRED)

# Set up the include directories.
include_directories(
"${PROJECT_SOURCE_DIR}/headers"
"${XQSDK_HEADER_PATH}"
"${CMAKE_INSTALL_PREFIX}/include"
/usr/local/include
)

if( UNIX AND NOT APPLE )
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lcurl")
set(PLATFORM_SPECIFIC_LIBS "curl -lpthread")
else()
set(PLATFORM_SPECIFIC_LIBS "CURL")
endif()

file(COPY ${PROJECT_SOURCE_DIR}/config/xq.ini DESTINATION  ${CMAKE_BINARY_DIR}/bin )

add_executable( starter )
target_sources( starter PRIVATE ${PROJECT_SOURCE_DIR}/starter/starter.c  ${PROJECT_SOURCE_DIR}/config/xq.ini   )
set(GROUP "Source Files")
source_group("Source Files" FILES  ${PROJECT_SOURCE_DIR}/starter/starter.c )
set(GROUP "Header Files")
set(GROUP "Config")
source_group("Config" FILES ${PROJECT_SOURCE_DIR}/config/xq.ini )
target_link_libraries( starter ${XQCSDK_LIB_PATH}  OpenSSL::SSL ${PLATFORM_SPECIFIC_LIBS} )


add_executable( proxy )
target_sources( proxy PRIVATE ${PROJECT_SOURCE_DIR}/proxy/proxy.c ${PROJECT_SOURCE_DIR}/headers/proxy.h  ${PROJECT_SOURCE_DIR}/config/xq.ini   )
set(GROUP "Source Files")
source_group("Source Files" FILES  ${PROJECT_SOURCE_DIR}/proxy/proxy.c )
set(GROUP "Header Files")
source_group("Header Files" FILES  ${PROJECT_SOURCE_DIR}/headers/proxy.h )
set(GROUP "Config")
target_link_libraries( proxy ${XQCSDK_LIB_PATH}  OpenSSL::SSL ${PLATFORM_SPECIFIC_LIBS} )
