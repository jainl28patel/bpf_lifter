cmake_minimum_required(VERSION 3.2)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON) # Ensure the compiler supports the specified standard

project(bpflifter)

find_library(LIBBPF NAMES bpf REQUIRED) # libbpf
if(NOT LIBBPF)
    message(FATAL_ERROR "libbpf not found. Install libbpf-dev or provide a path to CMake.")
endif()

# Create a static lib from src
add_library(${PROJECT_NAME} STATIC src/Lifter.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(${PROJECT_NAME} PUBLIC ${LIBBPF})

# Create a binary from cli
add_executable(bpflifter_cli cli/main.cpp)
target_link_libraries(bpflifter_cli PRIVATE bpflifter ${LIBBPF})  # Link libbpf only here