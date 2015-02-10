project(geoip)
cmake_minimum_required(VERSION 2.8)

add_definitions(-DPACKAGE_VERSION="1.6.4")

aux_source_directory(. SRC_LIST)
add_library(${PROJECT_NAME} ${SRC_LIST})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ws2_32)
