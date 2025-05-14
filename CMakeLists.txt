cmake_minimum_required(VERSION 3.16)
project(pqc_tls C)

set(CMAKE_C_STANDARD 11)

find_package(OpenSSL REQUIRED)

add_executable(pqc_tls_client client.c
        load_oqs.h
        load_oqs.c)
target_link_libraries(pqc_tls_client OpenSSL::SSL OpenSSL::Crypto oqsprovider oqs)

add_executable(pqc_tls_server server.c
        load_oqs.h
        load_oqs.c)
target_link_libraries(pqc_tls_server OpenSSL::SSL OpenSSL::Crypto oqsprovider oqs)
