cmake_minimum_required(VERSION 3.11)

project(server CXX)
set(CMAKE_CXX_STANDARD 20)

set(CMAKE_CXX_FLAGS "-g")

find_package(Boost REQUIRED COMPONENTS charconv json date_time)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Poco REQUIRED Net JWT)

add_executable(server
        src/main.cpp
        src/listener.cpp
        src/listener.h
        src/server_certificate.h
        src/session.cpp
        src/session.h
        src/request_handler.h
        src/request_handler.cpp
  )
target_link_libraries(server PRIVATE Boost::charconv Boost::json Boost::date_time
  Poco::JWT Poco::Net Threads::Threads OpenSSL::Crypto OpenSSL::SSL)
