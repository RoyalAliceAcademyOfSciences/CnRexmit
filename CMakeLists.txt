project(CnRexmit)
cmake_minimum_required(VERSION 2.8)

if(WIN32)
    include_directories(./WpdPack)
    include_directories(./libGeoIP)
    add_subdirectory(libGeoIP)
endif(WIN32)

aux_source_directory(. SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})

if(WIN32)
    #your WpdPack lib path
    LINK_DIRECTORIES(D:/Qt/projects/WpdPack/Lib/)
    find_library(WPCAPLIB wpcap)

    TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${WPCAPLIB} geoip ws2_32)
    add_definitions(-DHAVE_REMOTE)
    set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static -s")
endif(WIN32)

if(UNIX)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} pcap GeoIP)
endif(UNIX)
