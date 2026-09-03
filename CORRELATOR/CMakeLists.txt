cmake_minimum_required(VERSION 3.20)

project(TitanCorrelator
    VERSION     1.0.0
    DESCRIPTION "TITAN Correlator — cross-endpoint evidence join (reads other endpoints' JSONL logs, never writes into them)"
    LANGUAGES   CXX
)

set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

add_compile_definitions(
    _WIN32_WINNT=0x0A00
    WINVER=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)

# ── Executable ────────────────────────────────────────────────────────────────
add_executable(correlator
    main.cpp
    json_fields.cpp
    correlation_engine.cpp
    unified_stream_engine.cpp
    correlator_logger.cpp
    correlated_snapshot_writer.cpp
    evidence_envelope.cpp
    ipc_control_server.cpp
    log_tailer.cpp
)
target_include_directories(correlator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(correlator PRIVATE bcrypt advapi32)

# ── Non-admin logic-test target ───────────────────────────────────────────────
# Pure logic only (JSON extraction, join predicate, engine ingest+correlate
# with synthetic fixtures) -- no real file tailing, no Administrator needed.
add_executable(correlator_logic_test
    correlator_logic_test.cpp
    json_fields.cpp
    correlation_engine.cpp
)
target_include_directories(correlator_logic_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(unified_stream_engine_test
    unified_stream_engine_test.cpp
    json_fields.cpp
    correlation_engine.cpp
    unified_stream_engine.cpp
    correlated_snapshot_writer.cpp
    evidence_envelope.cpp
    log_tailer.cpp
)
target_link_libraries(unified_stream_engine_test PRIVATE bcrypt advapi32)
target_include_directories(unified_stream_engine_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# ── Non-admin IPC control channel integration test ────────────────────────────
add_executable(ipc_control_server_test
    ipc_control_server_test.cpp
    correlator_logger.cpp
    evidence_envelope.cpp
    ipc_control_server.cpp
)
target_include_directories(ipc_control_server_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ipc_control_server_test PRIVATE bcrypt advapi32)

if(MSVC)
    target_compile_options(correlator PRIVATE
        /W4 /WX /permissive- /Zc:__cplusplus /sdl
    )
    target_compile_options(correlator_logic_test PRIVATE
        /W4 /WX /permissive- /Zc:__cplusplus /sdl
    )
    target_compile_options(ipc_control_server_test PRIVATE
        /W4 /WX /permissive- /Zc:__cplusplus /sdl
    )
    target_compile_options(unified_stream_engine_test PRIVATE
        /W4 /WX /permissive- /Zc:__cplusplus /sdl
    )
    target_compile_options(correlator PRIVATE $<$<CONFIG:Debug>:/Od /RTC1 /MDd>)
    target_compile_options(correlator PRIVATE $<$<CONFIG:Release>:/O2 /GL /Oi /GS>)
    target_link_options(correlator PRIVATE $<$<CONFIG:Release>:/LTCG>)
    string(REPLACE "/W3" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
endif()

set_target_properties(correlator PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    PDB_OUTPUT_DIRECTORY     "${CMAKE_BINARY_DIR}/bin"
)
set_target_properties(correlator_logic_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    PDB_OUTPUT_DIRECTORY     "${CMAKE_BINARY_DIR}/bin"
)
set_target_properties(ipc_control_server_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    PDB_OUTPUT_DIRECTORY     "${CMAKE_BINARY_DIR}/bin"
)
set_target_properties(unified_stream_engine_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    PDB_OUTPUT_DIRECTORY     "${CMAKE_BINARY_DIR}/bin"
)

# Copy the default config template alongside the built executable so a
# fresh build is immediately runnable.
add_custom_command(TARGET correlator POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/correlator_config.txt"
        "$<TARGET_FILE_DIR:correlator>/correlator_config.txt"
    COMMENT "Copying correlator_config.txt next to the executable"
)
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/bin/logs")

enable_testing()
add_test(NAME correlator_logic_test COMMAND correlator_logic_test)
add_test(NAME ipc_control_server_test COMMAND ipc_control_server_test)
add_test(NAME unified_stream_engine_test COMMAND unified_stream_engine_test)

message(STATUS "---------------------------------------------------")
message(STATUS "  Project : ${PROJECT_NAME} ${PROJECT_VERSION}")
message(STATUS "  C++     : ${CMAKE_CXX_STANDARD}")
message(STATUS "  Output  : ${CMAKE_BINARY_DIR}/bin")
message(STATUS "---------------------------------------------------")
