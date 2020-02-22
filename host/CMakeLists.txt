cmake_minimum_required(VERSION 3.11)
project(xgboost LANGUAGES CXX C VERSION 0.90)
# openenclave
find_package(OpenEnclave CONFIG REQUIRED)
add_definitions(-D__SGX__)

#-- Options
option(BUILD_C_DOC "Build documentation for C APIs using Doxygen." OFF)
option(USE_OPENMP "Build with OpenMP support." ON)
## Bindings
option(JVM_BINDINGS "Build JVM bindings" OFF)
option(R_LIB "Build shared library for R package" OFF)
## Dev
option(GOOGLE_TEST "Build google tests" OFF)
option(USE_DMLC_GTEST "Use google tests bundled with dmlc-core submodule (EXPERIMENTAL)" OFF)
option(USE_NVTX "Build with cuda profiling annotations. Developers only." OFF)
set(NVTX_HEADER_DIR "" CACHE PATH "Path to the stand-alone nvtx header")
## CUDA
option(USE_CUDA  "Build with GPU acceleration" OFF)
option(USE_NCCL  "Build with NCCL to enable multi-GPU support." OFF)
option(BUILD_WITH_SHARED_NCCL "Build with shared NCCL library." OFF)
set(GPU_COMPUTE_VER "" CACHE STRING
  "Semicolon separated list of compute versions to be built against, e.g. '35;61'")
if (BUILD_WITH_SHARED_NCCL AND (NOT USE_NCCL))
  message(SEND_ERROR "Build XGBoost with -DUSE_NCCL=ON to enable BUILD_WITH_SHARED_NCCL.")
endif (BUILD_WITH_SHARED_NCCL AND (NOT USE_NCCL))
## Sanitizers
option(USE_SANITIZER "Use santizer flags" OFF)
option(SANITIZER_PATH "Path to sanitizes.")
set(ENABLED_SANITIZERS "address" "leak" CACHE STRING
  "Semicolon separated list of sanitizer names. E.g 'address;leak'. Supported sanitizers are
address, leak and thread.")
## Plugins
option(PLUGIN_LZ4 "Build lz4 plugin" OFF)
option(PLUGIN_DENSE_PARSER "Build dense parser plugin" OFF)

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

if (USE_CUDA)
  cmake_minimum_required(VERSION 3.12)
  SET(USE_OPENMP ON CACHE BOOL "CUDA requires OpenMP" FORCE)
  # `export CXX=' is ignored by CMake CUDA.
  set(CMAKE_CUDA_HOST_COMPILER ${CMAKE_CXX_COMPILER})
  message(STATUS "Configured CUDA host compiler: ${CMAKE_CUDA_HOST_COMPILER}")

  enable_language(CUDA)
  set(GEN_CODE "")
  format_gencode_flags("${GPU_COMPUTE_VER}" GEN_CODE)
  message(STATUS "CUDA GEN_CODE: ${GEN_CODE}")
endif (USE_CUDA)

add_custom_command(OUTPUT xgboost_u.h xgboost_u.c xgboost_args.h 
    DEPENDS ${CMAKE_SOURCE_DIR}/enclave/xgboost.edl
    COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/enclave/xgboost.edl)

# dmlc-core
msvc_use_static_runtime()
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
  # $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/host/dmlc-core/include>
  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
  $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include/rabit>)
  # $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/host/rabit/include/rabit>
  # $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/host/rabit/include>)
  # ${PROJECT_BINARY_DIR}/src)
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

# This creates its own shared library `xgboost4j'.
# if (JVM_BINDINGS)
  # add_subdirectory(${PROJECT_SOURCE_DIR}/jvm-packages)
# endif (JVM_BINDINGS)
#-- End shared library

#-- CLI for xgboost
# add_executable(runxgboost ${PROJECT_SOURCE_DIR}/src/cli_main.cc ${XGBOOST_OBJ_SOURCES})
# # For cli_main.cc only
# if (USE_OPENMP)
  # find_package(OpenMP REQUIRED)
  # target_compile_options(runxgboost PRIVATE ${OpenMP_CXX_FLAGS})
# endif (USE_OPENMP)
# target_include_directories(runxgboost
  # PRIVATE
  # ${PROJECT_SOURCE_DIR}/include
  # ${PROJECT_SOURCE_DIR}/dmlc-core/include
  # ${PROJECT_SOURCE_DIR}/rabit/include)
# target_link_libraries(runxgboost PRIVATE ${LINKED_LIBRARIES_PRIVATE})
# set_target_properties(
  # runxgboost PROPERTIES
  # OUTPUT_NAME xgboost
  # CXX_STANDARD 11
  # CXX_STANDARD_REQUIRED ON)
# # -- End CLI for xgboost
# 
# set_output_directory(runxgboost ${PROJECT_SOURCE_DIR})
set_output_directory(xgboost ${CMAKE_SOURCE_DIR}/build)
# # Ensure these two targets do not build simultaneously, as they produce outputs with conflicting names
# add_dependencies(xgboost runxgboost)

#-- Installing XGBoost
# if (R_LIB)
  # set_target_properties(xgboost PROPERTIES PREFIX "")
  # if (APPLE)
    # set_target_properties(xgboost PROPERTIES SUFFIX ".so")
  # endif (APPLE)
  # setup_rpackage_install_target(xgboost ${CMAKE_CURRENT_BINARY_DIR})
  # set(CMAKE_INSTALL_PREFIX "${CMAKE_CURRENT_BINARY_DIR}/dummy_inst")
# endif (R_LIB)
# if (MINGW)
  # set_target_properties(xgboost PROPERTIES PREFIX "")
# endif (MINGW)
# 
# if (BUILD_C_DOC)
  # include(cmake/Doc.cmake)
  # run_doxygen()
# endif (BUILD_C_DOC)
# 
include(GNUInstallDirs)
# # Exposing only C APIs.
# install(FILES
  # "${PROJECT_SOURCE_DIR}/include/xgboost/c_api.h"
  # DESTINATION
  # include/xgboost/)
# 
# install(TARGETS xgboost runxgboost
  # EXPORT XGBoostTargets
  # ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  # LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  # RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  # INCLUDES DESTINATION ${LIBLEGACY_INCLUDE_DIRS})
# install(EXPORT XGBoostTargets
  # FILE XGBoostTargets.cmake
  # NAMESPACE xgboost::
  # DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/xgboost)
# 
# include(CMakePackageConfigHelpers)
# configure_package_config_file(
  # ${CMAKE_CURRENT_LIST_DIR}/cmake/xgboost-config.cmake.in
  # ${CMAKE_CURRENT_BINARY_DIR}/cmake/xgboost-config.cmake
  # INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/xgboost)
# write_basic_package_version_file(
  # ${CMAKE_BINARY_DIR}/cmake/xgboost-config-version.cmake
  # VERSION ${XGBOOST_VERSION}
  # COMPATIBILITY AnyNewerVersion)
# install(
  # FILES
  # ${CMAKE_BINARY_DIR}/cmake/xgboost-config.cmake
  # ${CMAKE_BINARY_DIR}/cmake/xgboost-config-version.cmake
  # DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/xgboost)

#-- Test
# if (GOOGLE_TEST)
  # enable_testing()
  # # Unittests.
  # add_subdirectory(${PROJECT_SOURCE_DIR}/tests/cpp)
  # add_test(
    # NAME TestXGBoostLib
    # COMMAND testxgboost
    # WORKING_DIRECTORY ${PROJECT_BINARY_DIR})
# 
  # # CLI tests
  # configure_file(
    # ${PROJECT_SOURCE_DIR}/tests/cli/machine.conf.in
    # ${PROJECT_BINARY_DIR}/tests/cli/machine.conf
    # @ONLY)
  # add_test(
    # NAME TestXGBoostCLI
    # COMMAND runxgboost ${PROJECT_BINARY_DIR}/tests/cli/machine.conf
    # WORKING_DIRECTORY ${PROJECT_BINARY_DIR})
  # set_tests_properties(TestXGBoostCLI
    # PROPERTIES
    # PASS_REGULAR_EXPRESSION ".*test-rmse:0.087.*")
# endif (GOOGLE_TEST)

# For MSVC: Call msvc_use_static_runtime() once again to completely
# replace /MD with /MT. See https://github.com/dmlc/xgboost/issues/4462
# for issues caused by mixing of /MD and /MT flags
msvc_use_static_runtime()
