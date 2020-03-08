cmake_minimum_required(VERSION 3.11)
project(topxgboost LANGUAGES CXX C)

message(STATUS "CMake version ${CMAKE_VERSION}")
if (MSVC)
    cmake_minimum_required(VERSION 3.11)
endif (MSVC)

include(cmake/Utils.cmake)
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/modules")
cmake_policy(SET CMP0022 NEW)

set_default_configuration_release()

#-- Options
option(SIMULATE "Run enclave in simulation mode" OFF)
option(OBLIVIOUS "Enable oblivious training and inference" ON)

if (SIMULATE)
    message("\nBuilding enclave in simulation mode.\n")
else ()
    message("\nBuilding enclave in hardware mode.\n")
endif (SIMULATE)
if (OBLIVIOUS)
    message("\Enabling obliviousness.\n")
else ()
    message("\nDisabling obliviousness.\n")
endif (OBLIVIOUS)

add_subdirectory(${PROJECT_SOURCE_DIR}/host)
add_subdirectory(${PROJECT_SOURCE_DIR}/enclave)
