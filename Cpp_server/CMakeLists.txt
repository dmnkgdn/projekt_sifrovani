cmake_minimum_required(VERSION 3.10)
project(SecureChat)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

include_directories(src/shared)

add_executable(chat_server src/server/main.cpp src/server/chat_server.cpp src/shared/crypto.cpp)
add_executable(chat_client src/client/main.cpp src/client/chat_client.cpp src/shared/crypto.cpp)

target_link_libraries(chat_server PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(chat_client PRIVATE OpenSSL::SSL OpenSSL::Crypto)
