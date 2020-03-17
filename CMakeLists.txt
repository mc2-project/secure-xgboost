cmake_minimum_required(VERSION 3.11)
project(topxgboost LANGUAGES CXX C)

message(STATUS "CMake version ${CMAKE_VERSION}")
if (MSVC)
    cmake_minimum_required(VERSION 3.11)
endif (MSVC)

include(cmake/Utils.cmake)
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/modules")
cmake_policy(SET CMP0022 NEW)

# OE configuration options for enclave
set(OE_DEBUG 0
    CACHE STRING "Build enclave in debug mode (1) or release mode (0)")
set(OE_NUM_HEAP_PAGES 100000
    CACHE STRING "Number of enclave heap pages")
set(OE_NUM_STACK_PAGES 1024
    CACHE STRING "Number of enclave heap pages")
set(OE_NUM_TCS 1
    CACHE STRING "Maximum number of enclave threads")
set(OE_PRODUCT_ID 1
    CACHE STRING "Enclave product ID (ISVPRODID)")
set(OE_SECURITY_VERSION 1
    CACHE STRING "Enclave security version (ISVSVN)")

option(LOGGING
    "Enable enclave logger" ON)
option(SIMULATE
    "Build enclave in simulation mode" OFF)
option(OBLIVIOUS
    "Enable oblivious training and inference" ON)
option(USE_AVX2 
    "Use AVX2 instructions to speed up oblivious primitives" ON)

# Generate conf file
FILE(WRITE ${PROJECT_SOURCE_DIR}/enclave/xgboost.conf
    "Debug=${OE_DEBUG}\n"
    "NumHeapPages=${OE_NUM_HEAP_PAGES}\n"
    "NumStackPages=${OE_NUM_STACK_PAGES}\n"
    "NumTCS=${OE_NUM_TCS}\n"
    "ProductID=${OE_PRODUCT_ID}\n"
    "SecurityVersion=${OE_SECURITY_VERSION}\n"
)

if(OE_DEBUG STREQUAL 0)
    set(LOGGING OFF)
    set(SIMULATE OFF)
endif(OE_DEBUG STREQUAL 0)

if(LOGGING)
    message("\nEnabling enclave logger.\n")
else()
    message("\nEnclave logger disabled.\n")
endif(LOGGING)
if(SIMULATE)
    message("\nBuilding enclave in simulation mode.\n")
else()
    message("\nBuilding enclave in hardware mode.\n")
endif(SIMULATE)
if(OBLIVIOUS)
    message("\nEnabling obliviousness.\n")
else()
    message("\nDisabling obliviousness.\n")
endif(OBLIVIOUS)

set_default_configuration_release()

add_subdirectory(${PROJECT_SOURCE_DIR}/host)
add_subdirectory(${PROJECT_SOURCE_DIR}/enclave)
