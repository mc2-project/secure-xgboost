cmake_minimum_required(VERSION 3.11)
project(topxgboost LANGUAGES CXX C)

message(STATUS "CMake version ${CMAKE_VERSION}")
if (MSVC)
    cmake_minimum_required(VERSION 3.11)
endif (MSVC)

include(cmake/Utils.cmake)
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/modules")
cmake_policy(SET CMP0022 NEW)

## Bindings
option(JVM_BINDINGS "Build JVM bindings" OFF)

# Build options
set(SIGNER_PUB_FILE config/enclave_signer.pub
    CACHE STRING "Public key of enclave signing authority")
set(SIGNER_KEY_FILE config/enclave_signer.pem
    CACHE STRING "Private key of enclave signing authority")
set(CA_CERT_FILE config/root.crt
    CACHE STRING "Root certificate of CA for signing client identities")

# OE configuration options for enclave
set(OE_DEBUG 1
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
    "Use AVX2 instructions to speed up oblivious primitives" ON)
option(LVI_MITIGATION
    "Enable mitigations for LVI vulnerability" OFF)
set(LVI_MITIGATION_BINDIR "/opt/openenclave/lvi_mitigation_bin"
    CACHE STRING "Path to LVI mitigation dependencies")
option(CONSENSUS
    "Enable cryptographic multiparty consensus" ON)

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

# Generate file to hardcode signer public key and root CA into enclave
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
if(CONSENSUS)
    message("\nEnabling consensus.\n")
else()
    message("\nDisabling consensus.\n")
endif(CONSENSUS)
if(LVI_MITIGATION)
    message("\nEnabling LVI mitigation.\n")
else()
    message("\nDisabling LVI mitigation.\n")
endif(LVI_MITIGATION)

set_default_configuration_release()

set(OE_MIN_VERSION 0.17.1)
if (LVI_MITIGATION)
    # Configure the cmake to use customized compilation toolchain.
    # This package has to be added before `project()`.
    find_package(OpenEnclave-LVI-Mitigation ${OE_MIN_VERSION} CONFIG REQUIRED)
endif()
find_package(OpenEnclave ${OE_MIN_VERSION} CONFIG REQUIRED)
set(OE_CRYPTO_LIB
    mbedtls
    CACHE STRING "Crypto library used by enclaves.")

add_subdirectory(${PROJECT_SOURCE_DIR}/host)
add_subdirectory(${PROJECT_SOURCE_DIR}/enclave)

# This creates its own shared library `xgboost4j'.
if (JVM_BINDINGS)
	add_subdirectory(${PROJECT_SOURCE_DIR}/jvm-packages)
endif (JVM_BINDINGS)
#-- End shared library`
