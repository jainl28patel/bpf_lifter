cmake_minimum_required(VERSION 3.2)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(bpflifter)

# Find LLVM packages
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# Add LLVM definitions and include directories
add_definitions(${LLVM_DEFINITIONS})
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

# Get required LLVM libraries
llvm_map_components_to_libnames(llvm_libs
    Core
    Support
    IRReader
    Analysis
    Passes
    Target
    X86CodeGen
    X86AsmParser     # Added for x86 support
    X86Info          # Added for x86 support
    X86Desc         # Added for x86 support
    MCJit
    ExecutionEngine
    BitWriter
    TransformUtils
    ScalarOpts
    InstCombine
    Object
    MC
    MCParser
    Option
)

# libbpf
find_library(LIBBPF NAMES bpf REQUIRED)
if(NOT LIBBPF)
    message(FATAL_ERROR "libbpf not found. Install libbpf-dev or provide a path to CMake.")
endif()

# Add elfio
include_directories(${PROJECT_SOURCE_DIR}/ELFIO)

# Set compilation flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti -fPIC")

# Create a static lib from src
add_library(${PROJECT_NAME} STATIC 
    src/Lifter.cpp 
    src/Decompiler.cpp 
    src/elf_utils.cpp 
    src/instr_utils.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC 
    ${PROJECT_SOURCE_DIR}/include
)

# Link LLVM libraries correctly
target_link_libraries(${PROJECT_NAME} PUBLIC 
    ${LIBBPF}
    -Wl,--start-group
    ${llvm_libs}
    -Wl,--end-group
    -lpthread
    -ldl
    -lz
)

# Create a binary from cli
add_executable(bpflifter_cli cli/main.cpp)

# Link the CLI executable
target_link_libraries(bpflifter_cli PRIVATE 
    ${PROJECT_NAME}
    -Wl,--start-group
    ${llvm_libs}
    -Wl,--end-group
    -lpthread
    -ldl
    -lz
)