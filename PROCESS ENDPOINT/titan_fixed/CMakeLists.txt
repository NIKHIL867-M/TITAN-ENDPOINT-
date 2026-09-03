cmake_minimum_required(VERSION 3.20)

project(TitanProcess
    VERSION     3.0.0
    DESCRIPTION "TITAN V3 — Process ETW monitor, signal amplifier, noise suppressor"
    LANGUAGES   CXX
)

# ── C++ standard ─────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# ── Windows target ────────────────────────────────────────────────────────────
add_compile_definitions(
    _WIN32_WINNT=0x0A00
    WINVER=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)

# ── Source files ──────────────────────────────────────────────────────────────
set(SOURCES
    main.cpp
    agent.cpp
    event.cpp
    evidence_envelope.cpp
    filter.cpp
    logger.cpp
    process_monitor.cpp
    ipc_control_server.cpp
)

# ── Executable ────────────────────────────────────────────────────────────────
add_executable(titan_process ${SOURCES})

# ── Include paths ─────────────────────────────────────────────────────────────
target_include_directories(titan_process PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# ── Linked libraries ──────────────────────────────────────────────────────────
target_link_libraries(titan_process PRIVATE
    advapi32        # Token/SID: OpenProcessToken, LookupAccountSidW, etc.
    bcrypt          # BCrypt SHA-256 (fingerprint + bloom keys)
    crypt32         # CryptQueryObject, Authenticode cert extraction
    wintrust        # WinVerifyTrust — signature verification
    normaliz        # NormalizeString — Unicode NFC
    kernel32        # Standard Win32 runtime
    ntdll           # NtQueryInformationProcess (via GetProcAddress)
    tdh             # ETW decoding helpers
    secur32         # Secure32
    user32          # Win32 message/window support
    ole32           # CoCreateGuid
)

# ── Non-admin logic-test target ───────────────────────────────────────────────
# Exercises pure logic only (JSON escaping, FilterEngine 7-stage pipeline,
# bloom filter persistence, ProcessAccumulator capping) -- no ETW session, so
# it runs without Administrator privileges. process_monitor.h is included
# only for the free-standing ProcessAccumulator struct; process_monitor.cpp
# (which starts a real ETW session) is deliberately NOT linked in.
add_executable(process_logic_test
    process_logic_test.cpp
    event.cpp
    filter.cpp
)
target_include_directories(process_logic_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(process_logic_test PRIVATE
    advapi32
    bcrypt
    crypt32
    wintrust
    normaliz
)

# ── Non-admin IPC control channel integration test ────────────────────────────
# Links process_monitor.cpp for real (ProcessMonitor's constructor + accessors),
# but ProcessMonitor::Start() -- which opens the real ETW session -- is never
# called, so this needs no Administrator privileges either. Exercises the real
# ipc_control_server.cpp protocol end-to-end over a real named pipe.
add_executable(ipc_control_server_test
    ipc_control_server_test.cpp
    agent.cpp
    event.cpp
    evidence_envelope.cpp
    filter.cpp
    logger.cpp
    process_monitor.cpp
    ipc_control_server.cpp
)
target_include_directories(ipc_control_server_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ipc_control_server_test PRIVATE
    advapi32
    bcrypt
    crypt32
    wintrust
    normaliz
    kernel32
    ntdll
    tdh
    secur32
    user32
    ole32
)

# ── Compiler warnings & hardening ─────────────────────────────────────────────
if(MSVC)
    target_compile_options(titan_process PRIVATE
        /W4
        /WX
        /permissive-
        /Zc:__cplusplus
        /w44388
        /w44302
        /wd4068
        /wd4996 
        /wd4244# Suppress CRT deprecation (gmtime, etc.)
        /sdl
    )
    target_compile_options(process_logic_test PRIVATE
        /W4 /WX /permissive- /Zc:__cplusplus /w44388 /w44302 /wd4068 /wd4996 /wd4244 /sdl
    )
    target_compile_options(ipc_control_server_test PRIVATE
        /W4 /WX /permissive- /Zc:__cplusplus /w44388 /w44302 /wd4068 /wd4996 /wd4244 /sdl
    )

    # Debug
    target_compile_options(titan_process PRIVATE
        $<$<CONFIG:Debug>:/Od /RTC1 /MDd>
    )

    # Release — /GS retained deliberately (security agent, no /GS-)
    target_compile_options(titan_process PRIVATE
        $<$<CONFIG:Release>:/O2 /GL /Oi /GS>
    )
    target_link_options(titan_process PRIVATE
        $<$<CONFIG:Release>:/LTCG>
    )

    string(REPLACE "/W3" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
endif()

# ── Output directories ────────────────────────────────────────────────────────
set_target_properties(titan_process PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    PDB_OUTPUT_DIRECTORY     "${CMAKE_BINARY_DIR}/bin"
)
set_target_properties(process_logic_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    PDB_OUTPUT_DIRECTORY     "${CMAKE_BINARY_DIR}/bin"
)
set_target_properties(ipc_control_server_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    PDB_OUTPUT_DIRECTORY     "${CMAKE_BINARY_DIR}/bin"
)

# ── Non-admin CTest suite ─────────────────────────────────────────────────────
enable_testing()
add_test(NAME process_logic_test COMMAND process_logic_test)
add_test(NAME ipc_control_server_test COMMAND ipc_control_server_test)

# ── Create runtime directories at configure time ──────────────────────────────
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/logs")
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/data")   # Bloom filter persistence

# ── Install ───────────────────────────────────────────────────────────────────
install(TARGETS titan_process RUNTIME DESTINATION bin)

# ── Summary ───────────────────────────────────────────────────────────────────
message(STATUS "---------------------------------------------------")
message(STATUS "  Project : ${PROJECT_NAME} ${PROJECT_VERSION}")
message(STATUS "  C++     : ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build   : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Output  : ${CMAKE_BINARY_DIR}/bin")
message(STATUS "  Logs    : ${CMAKE_BINARY_DIR}/logs")
message(STATUS "  Data    : ${CMAKE_BINARY_DIR}/data  (bloom filters)")
message(STATUS "---------------------------------------------------")