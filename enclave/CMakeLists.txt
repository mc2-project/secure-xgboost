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
  ${CMAKE_CURRENT_BINARY_DIR})
target_compile_options(xgboost_enclave
  PRIVATE
  -U_FORTIFY_SOURCE 
  -fno-stack-protector
  -fno-strict-aliasing
  -D_GLIBCXX_USE_CXX11_ABI=0 
  -ftls-model=local-exec
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
  -D__SGX__
  -D__ENCLAVE__
  OE_API_VERSION=2
  -DDMLC_LOG_CUSTOMIZE=1  # enable custom logging
  ${XGBOOST_DEFINITIONS})

if(LOGGING)
  target_compile_definitions(xgboost_enclave PUBLIC -D__ENCLAVE_ENABLE_LOGGER__)
endif(LOGGING)
if(SIMULATE)
  target_compile_definitions(xgboost_enclave PUBLIC -D__ENCLAVE_SIMULATION__)
endif(SIMULATE)
if(OBLIVIOUS)
  target_compile_definitions(xgboost_enclave PUBLIC -D__ENCLAVE_OBLIVIOUS__)
endif(OBLIVIOUS)

target_link_libraries(xgboost_enclave openenclave::oeenclave openenclave::oelibcxx openenclave::oehostfs openenclave::oehostsock openenclave::oehostresolver)

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
