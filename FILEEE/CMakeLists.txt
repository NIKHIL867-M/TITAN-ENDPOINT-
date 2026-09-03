cmake_minimum_required(VERSION 3.20)

project(TITAN_FIM
    VERSION     1.0.0
    DESCRIPTION "TITAN - File Integrity Monitor (ETW-based, Windows)"
    LANGUAGES   CXX
)

# =============================================================================
# Platform guard — Windows-only (ETW, BCrypt, Win32 APIs)
# =============================================================================
if(NOT WIN32)
    message(FATAL_ERROR
        "TITAN FIM is Windows-only (ETW, BCrypt, and Win32 APIs required).\n"
        "Build on a Windows host with MSVC or Clang-CL.")
endif()

# =============================================================================
# Language standard
# FIX: Bumped from C++17 to C++20. TITAN was originally designed for C++20.
# =============================================================================
set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# =============================================================================
# Executable target
# =============================================================================
add_executable(file_test
    main_file_test.cpp
    file_etw_collector.cpp
    evidence_envelope.cpp
    ipc_control_server.cpp
    file_logger.cpp
    file_monitor.cpp
    file_processor.cpp
    file_tracker.cpp
)

add_executable(fim_logic_test
    fim_logic_test.cpp
    evidence_envelope.cpp
    file_logger.cpp
    file_monitor.cpp
    file_processor.cpp
    file_tracker.cpp
)

add_executable(fim_etw_probe fim_etw_probe.cpp)

add_executable(ipc_control_server_test
    ipc_control_server_test.cpp
    evidence_envelope.cpp
    ipc_control_server.cpp
    file_logger.cpp
    file_monitor.cpp
    file_processor.cpp
    file_tracker.cpp
)

target_include_directories(file_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_include_directories(fim_logic_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(ipc_control_server_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# =============================================================================
# Windows SDK libraries
#   tdh.lib      — TDH (Trace Data Helper) for ETW schema decode
#   advapi32.lib — StartTraceW / EnableTraceEx2 / ControlTraceW
#   bcrypt.lib   — BCryptOpenAlgorithmProvider / BCryptCreateHash (SHA-256)
#   psapi.lib    — QueryFullProcessImageNameW / GetModuleFileNameExW
# =============================================================================
target_link_libraries(file_test PRIVATE
    tdh
    advapi32
    bcrypt
    psapi
)
target_link_libraries(fim_logic_test PRIVATE bcrypt psapi)
target_link_libraries(ipc_control_server_test PRIVATE tdh advapi32 bcrypt psapi)

# =============================================================================
# Preprocessor defines
# =============================================================================
target_compile_definitions(file_test PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00     # target Windows 10 (required for ETW real-time mode)
)
target_compile_definitions(fim_logic_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
)
target_compile_definitions(fim_etw_probe PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
)
target_compile_definitions(ipc_control_server_test PRIVATE
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
)

# =============================================================================
# Compiler warnings
# =============================================================================
if(MSVC)
    target_compile_options(file_test PRIVATE
        /W4
        /WX
        /permissive-
        /wd4100     # unreferenced formal parameter (common in ETW callbacks)
        /wd4996     # deprecated POSIX names
    )
    target_compile_options(fim_logic_test PRIVATE
        /W4 /WX /permissive- /wd4100 /wd4996
    )
    target_compile_options(fim_etw_probe PRIVATE
        /W4 /WX /permissive- /wd4996
    )
    target_compile_options(ipc_control_server_test PRIVATE
        /W4 /WX /permissive- /wd4100 /wd4996
    )
else()
    target_compile_options(file_test PRIVATE
        -Wall -Wextra -Wpedantic
    )
endif()

enable_testing()
add_test(NAME fim_logic_test COMMAND fim_logic_test)
add_test(NAME ipc_control_server_test COMMAND ipc_control_server_test)

# =============================================================================
# UAC manifest — require Administrator elevation at launch.
# ETW kernel-file provider requires elevated privileges.
# =============================================================================
if(MSVC)
    set_target_properties(file_test PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
    )
endif()

# =============================================================================
# Output directories
# =============================================================================
set_target_properties(file_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY         "${CMAKE_BINARY_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG   "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
)

# Pre-create the logs directory so the first run doesn't fail.
add_custom_command(TARGET file_test POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "$<TARGET_FILE_DIR:file_test>/logs"
    COMMENT "Creating logs/ directory alongside executable"
)

# =============================================================================
# Summary
# =============================================================================
message(STATUS "")
message(STATUS "  TITAN FIM build configuration")
message(STATUS "  --------------------------------")
message(STATUS "  Target       : file_test")
message(STATUS "  C++ standard : ${CMAKE_CXX_STANDARD}")
message(STATUS "  Output dir   : ${CMAKE_BINARY_DIR}/bin")
message(STATUS "  Platform     : Windows (ETW kernel-file provider)")
message(STATUS "")
