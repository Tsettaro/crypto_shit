cmake_minimum_required(VERSION 3.24)
project(CryptoPDiddy CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

if(WIN32)
    # Automatically downloads pre-built Windows OpenSSL binaries.
    FetchContent_Declare(
        openssl
        URL "https://github.com/TaurusTLS-Developers/OpenSSL-Distribution/releases/download/v3.5.6/openssl-3.5.6-Windows-x64.zip"
    )
    FetchContent_MakeAvailable(openssl)

    find_path(OPENSSL_INCLUDE_DIR
        NAMES openssl/evp.h
        PATHS
            "${openssl_SOURCE_DIR}/include"
            "${openssl_SOURCE_DIR}/x64/include"
            "${openssl_SOURCE_DIR}/win64/include"
            "${openssl_SOURCE_DIR}/openssl-3.5.6/include"
            "${openssl_SOURCE_DIR}/openssl-3.5.6-Windows-x64/include"
        NO_DEFAULT_PATH
    )

    find_library(OPENSSL_CRYPTO_LIB
        NAMES libcrypto crypto
        PATHS
            "${openssl_SOURCE_DIR}/lib"
            "${openssl_SOURCE_DIR}/x64/lib"
            "${openssl_SOURCE_DIR}/win64/lib"
            "${openssl_SOURCE_DIR}/openssl-3.5.6/lib"
            "${openssl_SOURCE_DIR}/openssl-3.5.6-Windows-x64/lib"
        NO_DEFAULT_PATH
    )

    find_library(OPENSSL_SSL_LIB
        NAMES libssl ssl
        PATHS
            "${openssl_SOURCE_DIR}/lib"
            "${openssl_SOURCE_DIR}/x64/lib"
            "${openssl_SOURCE_DIR}/win64/lib"
            "${openssl_SOURCE_DIR}/openssl-3.5.6/lib"
            "${openssl_SOURCE_DIR}/openssl-3.5.6-Windows-x64/lib"
        NO_DEFAULT_PATH
    )

    find_file(OPENSSL_CRYPTO_DLL
        NAMES libcrypto-3-x64.dll libcrypto-3.dll
        PATHS
            "${openssl_SOURCE_DIR}/bin"
            "${openssl_SOURCE_DIR}/x64/bin"
            "${openssl_SOURCE_DIR}/win64/bin"
            "${openssl_SOURCE_DIR}/openssl-3.5.6/bin"
            "${openssl_SOURCE_DIR}/openssl-3.5.6-Windows-x64/bin"
        NO_DEFAULT_PATH
    )

    find_file(OPENSSL_SSL_DLL
        NAMES libssl-3-x64.dll libssl-3.dll
        PATHS
            "${openssl_SOURCE_DIR}/bin"
            "${openssl_SOURCE_DIR}/x64/bin"
            "${openssl_SOURCE_DIR}/win64/bin"
            "${openssl_SOURCE_DIR}/openssl-3.5.6/bin"
            "${openssl_SOURCE_DIR}/openssl-3.5.6-Windows-x64/bin"
        NO_DEFAULT_PATH
    )

    if(NOT OPENSSL_INCLUDE_DIR)
        file(GLOB_RECURSE OPENSSL_EVP_HEADERS "${openssl_SOURCE_DIR}/*/openssl/evp.h")
        if(OPENSSL_EVP_HEADERS)
            list(GET OPENSSL_EVP_HEADERS 0 OPENSSL_EVP_HEADER)
            get_filename_component(OPENSSL_HEADER_DIR "${OPENSSL_EVP_HEADER}" DIRECTORY)
            get_filename_component(OPENSSL_INCLUDE_DIR "${OPENSSL_HEADER_DIR}" DIRECTORY)
        endif()
    endif()

    if(NOT OPENSSL_CRYPTO_LIB)
        file(GLOB_RECURSE OPENSSL_CRYPTO_LIBS
            "${openssl_SOURCE_DIR}/*libcrypto*.lib"
            "${openssl_SOURCE_DIR}/*crypto*.lib"
            "${openssl_SOURCE_DIR}/*libcrypto*.dll.a"
        )
        if(OPENSSL_CRYPTO_LIBS)
            list(GET OPENSSL_CRYPTO_LIBS 0 OPENSSL_CRYPTO_LIB)
        endif()
    endif()

    if(NOT OPENSSL_SSL_LIB)
        file(GLOB_RECURSE OPENSSL_SSL_LIBS
            "${openssl_SOURCE_DIR}/*libssl*.lib"
            "${openssl_SOURCE_DIR}/*ssl*.lib"
            "${openssl_SOURCE_DIR}/*libssl*.dll.a"
        )
        if(OPENSSL_SSL_LIBS)
            list(GET OPENSSL_SSL_LIBS 0 OPENSSL_SSL_LIB)
        endif()
    endif()

    if(NOT OPENSSL_CRYPTO_DLL)
        file(GLOB_RECURSE OPENSSL_CRYPTO_DLLS
            "${openssl_SOURCE_DIR}/*libcrypto-3-x64.dll"
            "${openssl_SOURCE_DIR}/*libcrypto-3.dll"
        )
        if(OPENSSL_CRYPTO_DLLS)
            list(GET OPENSSL_CRYPTO_DLLS 0 OPENSSL_CRYPTO_DLL)
        endif()
    endif()

    if(NOT OPENSSL_SSL_DLL)
        file(GLOB_RECURSE OPENSSL_SSL_DLLS
            "${openssl_SOURCE_DIR}/*libssl-3-x64.dll"
            "${openssl_SOURCE_DIR}/*libssl-3.dll"
        )
        if(OPENSSL_SSL_DLLS)
            list(GET OPENSSL_SSL_DLLS 0 OPENSSL_SSL_DLL)
        endif()
    endif()

    if(NOT OPENSSL_INCLUDE_DIR OR NOT OPENSSL_CRYPTO_LIB OR NOT OPENSSL_SSL_LIB)
        message(FATAL_ERROR "Downloaded OpenSSL package does not contain the expected include/lib layout.")
    endif()
else()
    find_package(OpenSSL REQUIRED)
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_INCLUDE_DIR}")
    set(OPENSSL_CRYPTO_LIB OpenSSL::Crypto)
    set(OPENSSL_SSL_LIB OpenSSL::SSL)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(YKPIV REQUIRED ykpiv)

add_executable(EpstProject main.cpp CryptEpstein.h)

target_include_directories(EpstProject PRIVATE "${OPENSSL_INCLUDE_DIR}" ${YKPIV_INCLUDE_DIRS})
target_link_libraries(EpstProject PRIVATE "${OPENSSL_CRYPTO_LIB}" "${OPENSSL_SSL_LIB}" ${YKPIV_LIBRARIES})

if(WIN32)
    if(NOT OPENSSL_CRYPTO_DLL OR NOT OPENSSL_SSL_DLL)
        message(FATAL_ERROR "Downloaded OpenSSL package does not contain the expected DLL files.")
    endif()

    add_custom_command(TARGET EpstProject POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${OPENSSL_CRYPTO_DLL}"
        "${OPENSSL_SSL_DLL}"
        $<TARGET_FILE_DIR:EpstProject>
    )
endif()
