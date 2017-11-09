cmake_minimum_required(VERSION 3.8)
project(simple_http-https_client)

set(CMAKE_C_STANDARD C99)

link_libraries(-lssl -lcrypto -lws2_32)
set(SOURCE_FILES main.c)
add_executable(https_client ${SOURCE_FILES})