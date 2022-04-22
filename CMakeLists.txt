cmake_minimum_required(VERSION 3.16.3)

project(RN-store)


set(CMAKE_C_STANDARD 11)

add_library(crc16 STATIC
    src/crc16.c
)
target_include_directories(crc16
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

add_library(rdma STATIC
    src/rdma.c
)
target_include_directories(rdma
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)
add_library(rdma1 STATIC
    src/rdma.c
)
target_include_directories(rdma1
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)


add_executable(client
    src/client.c
)

target_link_libraries(client
    crc16 rdma
)

target_link_options(client
    PRIVATE
        -g -Wall -lpmem -libverbs 
)



add_executable(server
    src/server.c
)
target_link_directories(server
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)
target_link_options(server
    PRIVATE
        -g -Wall -lpmem -libverbs
)
target_link_libraries(
    rdma1
)