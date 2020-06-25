cmake_minimum_required(VERSION 3.11)
project(topxgboost LANGUAGES CXX C)

message(STATUS "CMake version ${CMAKE_VERSION}")
if (MSVC)
    cmake_minimum_required(VERSION 3.11)
endif (MSVC)

include(cmake/Utils.cmake)
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/modules")
cmake_policy(SET CMP0022 NEW)


# Build options
set(CLIENT_LIST user1 user2
    CACHE STRING "List of usernames of clients in federation")
set(SIGNER_PUB_FILE config/signer.pub
    CACHE STRING "Public key of enclave signing authority")
set(SIGNER_KEY_FILE config/signer.pem
    CACHE STRING "Private key of enclave signing authority")
set(CA_CERT_FILE config/signer.crt
    CACHE STRING "Root certificate of CA for signing client identities")

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
    "Enable enclave logger" OFF)
option(SIMULATE
    "Build enclave in simulation mode" OFF)
option(OBLIVIOUS
    "Enable oblivious training and inference" OFF)
option(USE_AVX2 
    "Use AVX2 instructions to speed up oblivious primitives" OFF)
option(LVI_MITIGATION
    "Enable mitigations for LVI vulnerability" OFF)
set(LVI_MITIGATION_BINDIR "/opt/openenclave/lvi_mitigation_bin"
    CACHE STRING "Path to LVI mitigation dependencies")

# Generate conf file
FILE(WRITE ${PROJECT_SOURCE_DIR}/enclave/xgboost.conf
    "Debug=${OE_DEBUG}\n"
    "NumHeapPages=${OE_NUM_HEAP_PAGES}\n"
    "NumStackPages=${OE_NUM_STACK_PAGES}\n"
    "NumTCS=${OE_NUM_TCS}\n"
    "ProductID=${OE_PRODUCT_ID}\n"
    "SecurityVersion=${OE_SECURITY_VERSION}\n"
)

# Read signer's public key
file(STRINGS ${SIGNER_PUB_FILE} MRSIGNER_PUBLIC_KEY_LINES)
set(MRSIGNER_PUBLIC_KEY "")
foreach(line IN LISTS MRSIGNER_PUBLIC_KEY_LINES)
    set(MRSIGNER_PUBLIC_KEY "${MRSIGNER_PUBLIC_KEY}\"${line}\\n\"\n")
endforeach()

# Read root certificate
file(STRINGS ${CA_CERT_FILE} CA_CERT_LINES)
set(CA_CERT "")
foreach(line IN LISTS CA_CERT_LINES)
    set(CA_CERT "${CA_CERT}\"${line}\\n\"\n")
endforeach()

# List of usernames of participating clients
set(CLIENT_NAMES "")
message("\nAuthorized client names:")
foreach(name ${CLIENT_LIST})
    message(${name})
    set(CLIENT_NAMES "${CLIENT_NAMES} \"${name}\",")
endforeach(name)
set(CLIENT_NAMES "{${CLIENT_NAMES}}")
list(LENGTH CLIENT_LIST NUM_CLIENTS)

# Generate file to hardcode usernames and keys into enclave
message(STATUS "cmake/attestation.h.in -> ${PROJECT_SOURCE_DIR}/include/enclave/attestation.h")
configure_file("cmake/attestation.h.in" "${PROJECT_SOURCE_DIR}/include/enclave/attestation.h")

if(OE_DEBUG STREQUAL 0)
    set(LOGGING OFF)
    set(SIMULATE OFF)
    message("\nBuilding enclave in hardware mode.\n")
else()
    message("\nBuilding enclave in debug mode.\n")
endif(OE_DEBUG STREQUAL 0)

if(LOGGING)
    message("\nEnabling enclave logger.\n")
else()
    message("\nEnclave logger disabled.\n")
endif(LOGGING)
if(SIMULATE)
    message("\nBuilding enclave in simulation mode.\n")
endif(SIMULATE)
if(OBLIVIOUS)
    message("\nEnabling obliviousness.\n")
else()
    message("\nDisabling obliviousness.\n")
endif(OBLIVIOUS)
if(LVI_MITIGATION)
    message("\nEnabling LVI mitigation.\n")
else()
    message("\nDisabling LVI mitigation.\n")
endif(LVI_MITIGATION)

set_default_configuration_release()

add_subdirectory(${PROJECT_SOURCE_DIR}/host)
add_subdirectory(${PROJECT_SOURCE_DIR}/enclave)
