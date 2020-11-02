cmake_minimum_required(VERSION 3.17)
project(DIS_EX01_Server)

set(CMAKE_CXX_STANDARD 14)

add_executable(DIS_EX01_Server main.cpp TCPServer.h TCPServer.cpp UDPServer.h UDPServer.cpp TCPv6Server.h TCPv6Server.cpp)