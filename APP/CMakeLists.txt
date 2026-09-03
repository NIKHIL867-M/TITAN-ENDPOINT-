cmake_minimum_required(VERSION 3.20)

project(TITAN_Application_Endpoint LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_definitions(
        UNICODE
        _UNICODE
        _WIN32_WINNT=0x0A00
        NTDDI_VERSION=0x0A000000
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
    )
    add_compile_options(
        /W4
        /WX
        /permissive-
        /utf-8
        /Zc:__cplusplus
        /EHsc
    )
endif()

set(APPLOG_SOURCES
    src/applog_monitor.cpp
    src/applog_etw_collector.cpp
    src/applog_event_subscriber.cpp
    src/applog_watchlist.cpp
    src/applog_decoder.cpp
    src/applog_logger.cpp
    src/application_discovery.cpp
    src/evidence_envelope.cpp
    src/ipc_control_server.cpp
    src/main_test.cpp
)

add_executable(application_endpoint ${APPLOG_SOURCES})
target_include_directories(application_endpoint PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(MSVC)
    target_precompile_headers(application_endpoint PRIVATE src/titan_pch.h)
    set_target_properties(application_endpoint PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endif()

target_link_libraries(application_endpoint PRIVATE
    tdh.lib
    wevtapi.lib
    advapi32.lib
    bcrypt.lib
    psapi.lib
    kernel32.lib
    user32.lib
    iphlpapi.lib
    ws2_32.lib
    wintrust.lib
    crypt32.lib
)

add_executable(application_logic_test
    src/application_logic_test.cpp
    src/applog_decoder.cpp
    src/applog_logger.cpp
    src/applog_watchlist.cpp
    src/application_discovery.cpp
    src/evidence_envelope.cpp
)
target_include_directories(application_logic_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(application_logic_test PRIVATE advapi32.lib bcrypt.lib kernel32.lib wintrust.lib crypt32.lib)
enable_testing()
add_test(NAME application_logic_test COMMAND application_logic_test)

# ── Non-admin IPC control channel integration test ────────────────────────────
add_executable(ipc_control_server_test
    src/ipc_control_server_test.cpp
    src/applog_monitor.cpp
    src/applog_etw_collector.cpp
    src/applog_event_subscriber.cpp
    src/applog_watchlist.cpp
    src/applog_decoder.cpp
    src/applog_logger.cpp
    src/application_discovery.cpp
    src/evidence_envelope.cpp
    src/ipc_control_server.cpp
)
target_include_directories(ipc_control_server_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(ipc_control_server_test PRIVATE
    tdh.lib wevtapi.lib advapi32.lib bcrypt.lib psapi.lib kernel32.lib
    user32.lib iphlpapi.lib ws2_32.lib wintrust.lib crypt32.lib
)
add_test(NAME ipc_control_server_test COMMAND ipc_control_server_test)

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    PROPERTY VS_STARTUP_PROJECT application_endpoint
)
