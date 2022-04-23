cmake_minimum_required(VERSION 3.16.3)

project(RN-store)


set(CMAKE_C_STANDARD 11)
include_directories(
    ${PROJECT_SOURCE_DIR}/include
)

add_library(crc16 STATIC
    src/crc16.c
)
add_library(rdma STATIC
    src/rdma.c
)
add_library(rdma1 STATIC
    src/rdma.c
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
target_link_options(server
    PRIVATE
        -g -Wall -lpmem -libverbs
)
target_link_libraries(server
    rdma1
)