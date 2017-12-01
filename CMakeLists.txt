cmake_minimum_required(VERSION 3.6.3)
project(simple_http-https_client)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES main.c)
add_executable(https_client ${SOURCE_FILES})

if (WIN32)
    target_link_libraries(https_client ws2_32)
    find_package(OpenSSL REQUIRED)
    include_directories(${OPENSSL_INCLUDE_DIR})
    target_link_libraries(https_client ${OPENSSL_LIBRARIES})
else()
    include_directories(/usr/local/opt/openssl/include)
    target_link_libraries(https_client -lssl -lcrypto)
endif()