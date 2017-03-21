cmake_minimum_required(VERSION 2.8)

project(print_pcap)

find_package( Boost COMPONENTS program_options REQUIRED )
if(NOT Boost_FOUND)
	message(SEND_ERROR "Failed to find Boost")
	return()
else()
	include_directories(${Boost_INCLUDE_DIR})
endif()
##########################################################
find_package( PCAP REQUIRED )
if(NOT PCAP_FOUND)
	message(SEND_ERROR "Failed to find Boost")
	return()
else()
	include_directories(${Boost_INCLUDE_DIR})
endif()
###########################################################
set(EXECUTABLE_OUTPUT_PATH "../bin/")

set(SRC_LIST src/main.cpp)

set(CMAKE_CXX_FLAGS "-std=c++14")

add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES} ${PCAP_LIBRARY})