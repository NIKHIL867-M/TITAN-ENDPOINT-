cmake_minimum_required(VERSION 3.20)

project(TITAN VERSION 4.0 LANGUAGES CXX)

# ============================================================================
# COMPILER / STANDARD
# ============================================================================
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================================
# MSVC-ONLY GUARD
# ============================================================================
if(NOT MSVC)
    message(FATAL_ERROR "TITAN V4 requires MSVC (cl.exe).")
endif()

# ============================================================================
# WINDOWS TARGET: Windows 10+
# ============================================================================
add_compile_definitions(
    _WIN32_WINNT=0x0A00
    WINVER=0x0A00
    NTDDI_VERSION=0x0A000000
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)

# ============================================================================
# MSVC FLAGS -- warnings are errors for project code.
# ============================================================================
add_compile_options(
    /W4
    /WX
    /permissive-
    /Zc:__cplusplus
    /utf-8
    /EHsc
    /MP
    /sdl            # SDL security checks
    /GS             # Buffer security checks — retained in all configs (security agent)
    /wd4100         # Unreferenced formal parameter — common in callback stubs
    /wd4505         # Unreferenced local function — common in header-only helpers
)

# Per-config overrides — one flag per generator expression (MSVC requires this)
add_compile_options(
    $<$<CONFIG:Debug>:/Od>
    $<$<CONFIG:Debug>:/RTC1>
    $<$<CONFIG:Debug>:/MDd>
    $<$<CONFIG:Release>:/O2>
    $<$<CONFIG:Release>:/GL>
    $<$<CONFIG:Release>:/Oi>
    $<$<CONFIG:Release>:/MD>
)

# ============================================================================
# NPCAP SDK -- REQUIRED
# ============================================================================
if(NOT DEFINED NPCAP_SDK_DIR)
    if(DEFINED ENV{NPCAP_SDK_DIR})
        set(NPCAP_SDK_DIR "$ENV{NPCAP_SDK_DIR}")
    elseif(EXISTS "$ENV{USERPROFILE}/Downloads/npcap-sdk-1.16/Include/pcap.h")
        set(NPCAP_SDK_DIR "$ENV{USERPROFILE}/Downloads/npcap-sdk-1.16")
    elseif(EXISTS "$ENV{USERPROFILE}/Downloads/npcap-sdk-1.13/Include/pcap.h")
        set(NPCAP_SDK_DIR "$ENV{USERPROFILE}/Downloads/npcap-sdk-1.13")
    elseif(EXISTS "C:/npcap-sdk/Include/pcap.h")
        set(NPCAP_SDK_DIR "C:/npcap-sdk")
    else()
        set(NPCAP_SDK_DIR "${CMAKE_SOURCE_DIR}/npcap-sdk")
    endif()
endif()

set(TITAN_HAS_NPCAP FALSE)
if(EXISTS "${NPCAP_SDK_DIR}/Include/pcap.h")
    set(TITAN_HAS_NPCAP TRUE)
    message(STATUS "Npcap SDK found: ${NPCAP_SDK_DIR}")
else()
    message(FATAL_ERROR "Npcap SDK not found.\nTITAN V4 is a network endpoint and requires Npcap SDK.\nSet NPCAP_SDK_DIR or install the SDK to one of the auto-detected locations.")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib/x64")
else()
    set(NPCAP_LIB_DIR "${NPCAP_SDK_DIR}/Lib")
endif()


# ============================================================================
# SOURCE FILES
# ============================================================================
set(TITAN_SOURCES
    main.cpp
    agent.cpp
    event.cpp
    evidence_envelope.cpp
    ipc_control_server.cpp
    logger.cpp
    network_monitor.cpp
    protocol_decoder.cpp
)

set(TITAN_HEADERS
    agent.h
    event.h
    evidence_envelope.h
    ipc_control_server.h
    logger.h
    network_monitor.h
    protocol_decoder.h
)


# ============================================================================
# EXECUTABLE
# ============================================================================
add_executable(titan ${TITAN_SOURCES} ${TITAN_HEADERS})

add_executable(protocol_decoder_test
    protocol_decoder_test.cpp
    protocol_decoder.cpp
)
target_include_directories(protocol_decoder_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
)
add_executable(ipc_control_server_test
    ipc_control_server_test.cpp
    agent.cpp
    event.cpp
    evidence_envelope.cpp
    ipc_control_server.cpp
    logger.cpp
    network_monitor.cpp
    protocol_decoder.cpp
)
target_include_directories(ipc_control_server_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${NPCAP_SDK_DIR}/Include"
)
target_link_directories(ipc_control_server_test PRIVATE "${NPCAP_LIB_DIR}")
target_link_libraries(ipc_control_server_test PRIVATE
    advapi32 bcrypt iphlpapi ws2_32 wpcap Packet
)

enable_testing()
add_test(NAME protocol_decoder_test COMMAND protocol_decoder_test)
add_test(NAME ipc_control_server_test COMMAND ipc_control_server_test)

# ============================================================================
# INCLUDE DIRS
# ============================================================================
target_include_directories(titan PRIVATE ${CMAKE_SOURCE_DIR})

# Npcap is required for this network endpoint
target_include_directories(titan PRIVATE "${NPCAP_SDK_DIR}/Include")
target_link_directories(titan PRIVATE "${NPCAP_LIB_DIR}")

# ============================================================================
# LINK LIBRARIES
# ============================================================================
target_link_libraries(titan PRIVATE
    advapi32
    bcrypt          # BCrypt SHA-256 (evidence_envelope.h self-hash)
    iphlpapi        # GetExtendedTcpTable / GetExtendedUdpTable / GetAdaptersAddresses
    ws2_32          # Winsock2
)

# Npcap required
target_link_libraries(titan PRIVATE wpcap Packet)

# ============================================================================
# SUBSYSTEM: Console + UAC manifest
# ============================================================================
set_target_properties(titan PROPERTIES WIN32_EXECUTABLE FALSE)

# UAC elevation manifest — requireAdministrator
# Write the flag inline. Using a CMake variable here causes VS to crash
# with 'Value cannot be null / Parameter name: key'.
target_link_options(titan PRIVATE
    "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
)

install(TARGETS titan DESTINATION bin)
