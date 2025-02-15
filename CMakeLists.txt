cmake_minimum_required(VERSION 3.2)

project(bpflifter)

# Create a static lib from src
add_library(${PROJECT_NAME} STATIC src/Lifter.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR}/include)

# Create a binary from cli
add_executable(bpflifter_cli cli/main.cpp)
target_link_libraries(bpflifter_cli PRIVATE bpflifter)