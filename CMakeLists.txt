cmake_minimum_required(VERSION 3.11)

project(server CXX)
set(CMAKE_CXX_STANDARD 20)

set(CMAKE_CXX_FLAGS "-g")

find_package(Boost REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Poco REQUIRED Net JWT)

add_executable(server
        main.cpp
        listener.cpp
        listener.h
        server_certificate.h
        session.cpp
        session.h
        request_handler.h
        request_handler.cpp
  )
  target_link_libraries(server PRIVATE Poco::JWT Poco::Net Threads::Threads OpenSSL::Crypto OpenSSL::SSL)
