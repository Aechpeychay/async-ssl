cmake_minimum_required(VERSION 3.11)

project(server CXX)
set(CMAKE_CXX_STANDARD 20)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

set( CMAKE_CXX_FLAGS "-g")

find_package(Boost 1.78.0 REQUIRED COMPONENTS charconv)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

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
target_link_libraries(server PRIVATE Boost::charconv Threads::Threads OpenSSL::Crypto OpenSSL::SSL)
