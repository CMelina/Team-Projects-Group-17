cmake_minimum_required(VERSION 3.16)
project(secure_transfer)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_executable(secure_transfer
        main.cpp
        src/crypto.cpp
        src/secure_transfer.h
        src/secure_transfer.cpp
)

target_include_directories(secure_transfer PRIVATE
        ${OPENSSL_INCLUDE_DIR}
        src
)

target_link_libraries(secure_transfer
        OpenSSL::Crypto
)
