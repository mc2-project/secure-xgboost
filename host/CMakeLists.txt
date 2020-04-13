cmake_minimum_required(VERSION 3.11)
project(xgboost LANGUAGES CXX C VERSION 0.90)
# openenclave
find_package(OpenEnclave CONFIG REQUIRED)

## Deprecation warning
if (USE_AVX)
  message(WARNING "The option 'USE_AVX' is deprecated as experimental AVX features have been removed from xgboost.")
endif (USE_AVX)

# Sanitizer
if (USE_SANITIZER)
  # Older CMake versions have had troubles with Sanitizer
  cmake_minimum_required(VERSION 3.12)
  include(cmake/Sanitizer.cmake)
  enable_sanitizers("${ENABLED_SANITIZERS}")
endif (USE_SANITIZER)

add_custom_command(OUTPUT xgboost_u.h xgboost_u.c xgboost_args.h 
    DEPENDS ${CMAKE_SOURCE_DIR}/enclave/xgboost.edl
    COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/enclave/xgboost.edl)

# dmlc-core
add_subdirectory(${PROJECT_SOURCE_DIR}/dmlc-core)
set_target_properties(dmlc PROPERTIES
  CXX_STANDARD 11
  CXX_STANDARD_REQUIRED ON
  POSITION_INDEPENDENT_CODE ON)
list(APPEND LINKED_LIBRARIES_PRIVATE dmlc)

# rabit
# full rabit doesn't build on windows, so we can't import it as subdirectory
if(MINGW OR R_LIB)
  set(RABIT_SOURCES
    rabit/src/engine_empty.cc
    rabit/src/c_api.cc)
else ()
  set(RABIT_SOURCES
    rabit/src/allreduce_base.cc
    rabit/src/allreduce_robust.cc
    rabit/src/engine.cc
    rabit/src/c_api.cc)
endif (MINGW OR R_LIB)
add_library(rabit STATIC ${RABIT_SOURCES} ${PROJECT_BINARY_DIR}/xgboost_u.c)
target_include_directories(rabit PRIVATE
  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include/rabit>)
target_link_libraries(rabit PRIVATE ${LINKED_LIBRARIES_PRIVATE} openenclave::oehostapp mbedcrypto mbedtls)
set_target_properties(rabit
  PROPERTIES
  CXX_STANDARD 11
  CXX_STANDARD_REQUIRED ON
  POSITION_INDEPENDENT_CODE ON)
list(APPEND LINKED_LIBRARIES_PRIVATE rabit)

# core xgboost
add_subdirectory(${PROJECT_SOURCE_DIR}/src)
set(XGBOOST_OBJ_SOURCES "${XGBOOST_OBJ_SOURCES};$<TARGET_OBJECTS:objxgboost>")

#-- Shared library
add_library(xgboost SHARED ${XGBOOST_OBJ_SOURCES} ${PLUGINS_SOURCES})
target_include_directories(xgboost
  INTERFACE
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include>
  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>)
target_link_libraries(xgboost PRIVATE ${LINKED_LIBRARIES_PRIVATE} openenclave::oehostapp mbedcrypto mbedtls)

set_output_directory(xgboost ${CMAKE_SOURCE_DIR}/build)
