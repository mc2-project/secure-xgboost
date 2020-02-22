cmake_minimum_required(VERSION 3.11)
project(securexgboost LANGUAGES CXX C)

set(RABIT_SOURCES
    rabit/src/allreduce_base.cc
    rabit/src/allreduce_robust.cc 
    rabit/src/ssl_socket.cc 
    rabit/src/ssl_attestation.cc 
    rabit/src/engine.cc
    rabit/src/c_api.cc)
file(GLOB_RECURSE CPU_SOURCES dmlc-core/*.cc src/*.cc)
list(REMOVE_ITEM CPU_SOURCES ${PROJECT_SOURCE_DIR}/src/cli_main.cc)

set(CMAKE_CXX_STANDARD 11)

include(CheckCXXSourceCompiles)
check_cxx_source_compiles("
#include <xmmintrin.h>
int main() {
  char data = 0;
  const char* address = &data;
  _mm_prefetch(address, _MM_HINT_NTA);
  return 0;
}
" XGBOOST_MM_PREFETCH_PRESENT)
check_cxx_source_compiles("
int main() {
  char data = 0;
  const char* address = &data;
  __builtin_prefetch(address, 0, 0);
  return 0;
}
" XGBOOST_BUILTIN_PREFETCH_PRESENT)

find_package(OpenEnclave CONFIG REQUIRED)

## Add plugins to source files
#if (PLUGIN_LZ4)
#  list(APPEND PLUGINS_SOURCES ${PROJECT_SOURCE_DIR}/plugin/lz4/sparse_page_lz4_format.cc)
#  list(APPEND SRC_LIBS lz4)
#endif (PLUGIN_LZ4)
#if (PLUGIN_DENSE_PARSER)
#  list(APPEND PLUGINS_SOURCES ${PROJECT_SOURCE_DIR}/plugin/dense_parser/dense_libsvm.cc)
#endif (PLUGIN_DENSE_PARSER)

#-- Object library
# Object library is necessary for jvm-package, which creates its own shared
# library.
#if (USE_CUDA)
#  file(GLOB_RECURSE CUDA_SOURCES *.cu)
#  add_library(objxgboost OBJECT ${CPU_SOURCES} ${CUDA_SOURCES} ${PLUGINS_SOURCES})
#  target_compile_definitions(objxgboost
#    PRIVATE -DXGBOOST_USE_CUDA=1)
#  target_include_directories(objxgboost PRIVATE ${PROJECT_SOURCE_DIR}/cub/)
#  target_compile_options(objxgboost PRIVATE
#    $<$<COMPILE_LANGUAGE:CUDA>:--expt-extended-lambda>
#    $<$<COMPILE_LANGUAGE:CUDA>:--expt-relaxed-constexpr>
#    $<$<COMPILE_LANGUAGE:CUDA>:-lineinfo>
#    $<$<AND:$<NOT:$<CXX_COMPILER_ID:MSVC>>,$<COMPILE_LANGUAGE:CUDA>>:--std=c++11>
#    $<$<COMPILE_LANGUAGE:CUDA>:${GEN_CODE}>)
#  
#  if (USE_NCCL)
#    find_package(Nccl REQUIRED)
#    target_include_directories(objxgboost PRIVATE ${NCCL_INCLUDE_DIR})
#    target_compile_definitions(objxgboost PRIVATE -DXGBOOST_USE_NCCL=1)
#    list(APPEND SRC_LIBS ${NCCL_LIBRARY})
#  endif (USE_NCCL)
#  
#  if (USE_NVTX)
#    target_include_directories(objxgboost PRIVATE "${NVTX_HEADER_DIR}")
#    target_compile_definitions(objxgboost PRIVATE -DXGBOOST_USE_NVTX=1)
#  endif (USE_NVTX)
#  
#  # OpenMP is mandatory for cuda version
#  find_package(OpenMP REQUIRED)
#  target_compile_options(objxgboost PRIVATE  
#    $<$<COMPILE_LANGUAGE:CUDA>:-Xcompiler=${OpenMP_CXX_FLAGS}>
#  )
#  
#  set_target_properties(objxgboost PROPERTIES
#    CUDA_SEPARABLE_COMPILATION OFF)
#else (USE_CUDA)
#  add_library(objxgboost OBJECT ${CPU_SOURCES} ${PLUGINS_SOURCES})
#endif (USE_CUDA)

# Check endianness
include(TestBigEndian)
test_big_endian(BIG_ENDIAN)
if(BIG_ENDIAN)
    set(DMLC_CMAKE_LITTLE_ENDIAN 0)
else()
    set(DMLC_CMAKE_LITTLE_ENDIAN 1)
endif()

message("../host/dmlc-core/cmake/build_config.h.in -> ${PROJECT_SOURCE_DIR}/../host/dmlc-core/include/dmlc/build_config.h")
configure_file("../host/dmlc-core/cmake/build_config.h.in" "${PROJECT_SOURCE_DIR}/../host/dmlc-core/include/dmlc/build_config.h")

add_custom_command(OUTPUT xgboost_t.h xgboost_t.c xgboost_args.h 
    DEPENDS ${PROJECT_SOURCE_DIR}/xgboost.edl
    COMMAND openenclave::oeedger8r --trusted ${PROJECT_SOURCE_DIR}/xgboost.edl)

add_executable(xgboost_enclave ${PROJECT_SOURCE_DIR}/ecalls.cpp ${CPU_SOURCES} ${RABIT_SOURCES} ${CMAKE_CURRENT_BINARY_DIR}/xgboost_t.c)


target_include_directories(xgboost_enclave
  PRIVATE
  ${PROJECT_SOURCE_DIR}/../include
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/include/dmlc-core/include
  ${PROJECT_SOURCE_DIR}/include/rabit/include
  # ${PROJECT_SOURCE_DIR}/../dmlc-core/include
  # ${PROJECT_SOURCE_DIR}/../rabit/include
  ${CMAKE_CURRENT_BINARY_DIR})
target_compile_options(xgboost_enclave
  PRIVATE
  -D__SGX__
  -D__ENCLAVE__
  -U_FORTIFY_SOURCE 
  -fno-stack-protector
  -fno-strict-aliasing
  -D_GLIBCXX_USE_CXX11_ABI=0 
  -ftls-model=local-exec
  #-D__thread='^-^'
  #$<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:CXX>>:/MP>
  #$<$<AND:$<NOT:$<CXX_COMPILER_ID:MSVC>>,$<COMPILE_LANGUAGE:CXX>>:-funroll-loops>)
  )
if (WIN32 AND MINGW)
  target_compile_options(xgboost_enclave PUBLIC -static-libstdc++)
endif (WIN32 AND MINGW)

set_target_properties(xgboost_enclave PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  CXX_STANDARD 11
  CXX_STANDARD_REQUIRED ON)
target_compile_definitions(xgboost_enclave
  PRIVATE
  OE_API_VERSION=2
  -DDMLC_LOG_CUSTOMIZE=1  # enable custom logging
  #$<$<NOT:$<CXX_COMPILER_ID:MSVC>>:_MWAITXINTRIN_H_INCLUDED>
  ${XGBOOST_DEFINITIONS})

target_link_libraries(xgboost_enclave openenclave::oeenclave openenclave::oelibcxx openenclave::oehostfs openenclave::oehostsock openenclave::oehostresolver)
#if (XGBOOST_MM_PREFETCH_PRESENT)
#  target_compile_definitions(objxgboost
#    PRIVATE
#    -DXGBOOST_MM_PREFETCH_PRESENT=1)
#endif(XGBOOST_MM_PREFETCH_PRESENT)
#if (XGBOOST_BUILTIN_PREFETCH_PRESENT)
#  target_compile_definitions(objxgboost
#    PRIVATE
#    -DXGBOOST_BUILTIN_PREFETCH_PRESENT=1)
#endif (XGBOOST_BUILTIN_PREFETCH_PRESENT)
#
#if (USE_OPENMP)
#  find_package(OpenMP REQUIRED)
#  if (OpenMP_CXX_FOUND OR OPENMP_FOUND)
#    target_compile_options(objxgboost PRIVATE  $<$<COMPILE_LANGUAGE:CXX>:${OpenMP_CXX_FLAGS}>)
#    if ((NOT OpenMP_CXX_LIBRARIES) AND (NOT MSVC))  # old CMake doesn't define this variable
#      set(OpenMP_CXX_LIBRARIES "gomp;pthread")
#    endif ((NOT OpenMP_CXX_LIBRARIES) AND (NOT MSVC))
#    list(APPEND SRC_LIBS ${OpenMP_CXX_LIBRARIES})
#    set(LINKED_LIBRARIES_PRIVATE "${LINKED_LIBRARIES_PRIVATE};${SRC_LIBS}" PARENT_SCOPE)
#  endif (OpenMP_CXX_FOUND OR OPENMP_FOUND)
#endif (USE_OPENMP)
#
# For MSVC: Call msvc_use_static_runtime() once again to completely
# replace /MD with /MT. See https://github.com/dmlc/xgboost/issues/4462
# for issues caused by mixing of /MD and /MT flags
#msvc_use_static_runtime()


# Generate key
# add_custom_command(OUTPUT private.pem public.pem
#     COMMAND openssl genrsa -out private.pem -3 3072
#     COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(OUTPUT xgboost_enclave.signed
	DEPENDS xgboost_enclave xgboost.conf private.pem
    COMMAND openenclave::oesign sign -e $<TARGET_FILE:xgboost_enclave> -c ${PROJECT_SOURCE_DIR}/xgboost.conf -k ${PROJECT_SOURCE_DIR}/private.pem)

# Dump enclave info
add_custom_command(OUTPUT xgboost_enclave.info
  DEPENDS xgboost_enclave.signed 
  COMMAND openenclave::oesign dump -e xgboost_enclave.signed > xgboost_enclave.info)

add_custom_target(sign ALL DEPENDS xgboost_enclave.signed)
add_custom_target(info ALL DEPENDS xgboost_enclave.info)

#-- End object library
