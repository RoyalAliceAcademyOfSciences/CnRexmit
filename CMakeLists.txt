project(CnRexmit)
cmake_minimum_required(VERSION 2.8)
include_directories(./WpdPack)
include_directories(./libGeoIP)
aux_source_directory(./libGeoIP SRC_LIST)
aux_source_directory(. SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})

if(WIN32)
    #your WpdPack lib path
    LINK_DIRECTORIES(D:/Qt/projects/WpdPack/Lib/)

    find_library(WPCAPLIB wpcap)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${WPCAPLIB} ws2_32)
    add_definitions(-DHAVE_REMOTE)
    set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static -s")
endif(WIN32)


