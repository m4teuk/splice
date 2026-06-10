cmake_minimum_required(VERSION 3.22)
project(splice LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

option(SPL_BUILD_TESTS "Build unit tests" ON)

# Capture the short git SHA at configure time so `spl --version` identifies which
# commit a build came from — important for the rolling binaries published from main
# (see .github/workflows/release.yml). Stale if you build without reconfiguring; CI
# always configures fresh. Falls back to "unknown" outside a git checkout.
execute_process(
  COMMAND git -C ${CMAKE_SOURCE_DIR} rev-parse --short HEAD
  OUTPUT_VARIABLE SPL_GIT_SHA
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET)
if(NOT SPL_GIT_SHA)
  set(SPL_GIT_SHA "unknown")
endif()

include(FetchContent)

# --- Corrosion: CMake <-> Cargo integration for the Rust shim crate (native/) ---
# Handles building the staticlib and pulling in the transitive native libraries
# a Rust staticlib needs (pthread/dl/m/...), which is the fiddly part of linking
# Rust into C++.
FetchContent_Declare(
  Corrosion
  GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
  GIT_TAG v0.6.1
)
FetchContent_MakeAvailable(Corrosion)

corrosion_import_crate(MANIFEST_PATH ${CMAKE_SOURCE_DIR}/native/Cargo.toml)

# --- spl_proto: pure wire codecs (no I/O), shared by the binary and the tests ---
add_library(spl_proto STATIC
  src/proto/frame.cpp
  src/proto/pairing.cpp
  src/proto/relay.cpp
)
target_include_directories(spl_proto PUBLIC ${CMAKE_SOURCE_DIR}/src)

# --- spl_core: pure server/runtime logic (no TLS), unit-testable ---
add_library(spl_core STATIC
  src/common/config.cpp
  src/net/endpoint.cpp
  src/server/relay_table.cpp
  src/server/rate_limit.cpp
  src/server/code_alloc.cpp
)
target_include_directories(spl_core PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(spl_core PUBLIC spl_proto)

# --- spl_net: sockets + TLS (OpenSSL), shared by server and peer ---
find_package(OpenSSL REQUIRED)
add_library(spl_net STATIC
  src/net/socket.cpp
  src/net/tls.cpp
  src/net/poller.cpp
)
target_include_directories(spl_net PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(spl_net PUBLIC spl_core OpenSSL::SSL OpenSSL::Crypto)

# --- spl_crypto: HKDF/HMAC/AEAD (OpenSSL) + SPAKE2 (Rust shim) ---
add_library(spl_crypto STATIC
  src/crypto/aead.cpp
  src/crypto/spake2.cpp
)
target_include_directories(spl_crypto PUBLIC ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/native/include)
# SPAKE2 symbols (spl_spake2_*) live in spl_native and resolve at final link.
target_link_libraries(spl_crypto PUBLIC spl_proto OpenSSL::Crypto)

# --- lwIP: userspace TCP/IP stack (NO_SYS, IPv6-only) ---
set(LWIP_DIR ${CMAKE_SOURCE_DIR}/third_party/lwip)
set(LWIP_INCLUDE_DIRS
  ${CMAKE_SOURCE_DIR}/src/lwip_port
  ${LWIP_DIR}/src/include
)
include(${LWIP_DIR}/src/Filelists.cmake)  # defines the lwipcore target (EXCLUDE_FROM_ALL)
# Compile our NO_SYS port (sys_now) into lwipcore so it resolves regardless of link order.
target_sources(lwipcore PRIVATE ${CMAKE_SOURCE_DIR}/src/lwip_port/sys_port.c)
# lwIP defines htons/ntohs/htonl/ntohl, which clang (macOS) flags as redefining the
# SDK's identical macros. Same behaviour; silence the noise on clang only.
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
  target_compile_options(lwipcore PRIVATE -Wno-macro-redefined)
endif()
add_library(spl_lwip INTERFACE)
target_include_directories(spl_lwip INTERFACE ${LWIP_INCLUDE_DIRS})
target_link_libraries(spl_lwip INTERFACE lwipcore)

# --- spl_peer: pairing client + connection store ---
add_library(spl_peer STATIC
  src/peer/store.cpp
  src/peer/pairing.cpp
  src/peer/wg.cpp
  src/peer/pathman.cpp
  src/peer/netstack.cpp
  src/peer/pipes.cpp
  src/peer/daemon.cpp
  src/peer/daemon_client.cpp
  src/peer/serve_get.cpp
  src/peer/chat.cpp
  src/peer/peer_cmd.cpp
)
# native FFI (keygen/random/spake2) resolves at final link against spl_native.
target_link_libraries(spl_peer PUBLIC spl_crypto spl_net spl_core spl_lwip)
# netstack.cpp includes lwIP headers — silence the htons/ntohs redefinition noise
# on clang (see lwipcore above).
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  target_compile_options(spl_peer PRIVATE -Wno-macro-redefined)
endif()

# --- spl_server: relay + pairing rendezvous + entrypoint ---
find_package(Threads REQUIRED)
add_library(spl_server STATIC
  src/server/relay_server.cpp
  src/server/pairing_server.cpp
  src/server/server_main.cpp
)
target_link_libraries(spl_server PUBLIC spl_net spl_core Threads::Threads)

# --- spl binary ---
add_executable(spl
  src/main.cpp
)
target_include_directories(spl PRIVATE
  ${CMAKE_SOURCE_DIR}/native/include   # cbindgen-generated spl_native.h (later phases)
)
# Corrosion names the imported target after the crate (lib) name, spl_native.
# (spl_proto arrives transitively via spl_peer/spl_server; listing it again makes
# the new Apple linker warn about a duplicate library.)
target_link_libraries(spl PRIVATE spl_peer spl_server spl_native)
target_compile_definitions(spl PRIVATE SPL_GIT_SHA="${SPL_GIT_SHA}")

# The new Apple linker (ld-prime) warns about duplicate libraries pulled in
# transitively, e.g. -lSystem from the Rust staticlib. Silence it where the flag
# exists; a no-op on GNU/other linkers (the check fails and it's skipped).
include(CheckLinkerFlag)
check_linker_flag(CXX "-Wl,-no_warn_duplicate_libraries" SPL_HAVE_NO_WARN_DUP_LIBS)
if(SPL_HAVE_NO_WARN_DUP_LIBS)
  target_link_options(spl PRIVATE "-Wl,-no_warn_duplicate_libraries")
endif()

# `cmake --install build --prefix /usr/local` -> /usr/local/bin/spl (see docs/DEPLOY.md).
install(TARGETS spl RUNTIME DESTINATION bin)

# --- tests ---
if(SPL_BUILD_TESTS)
  enable_testing()
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)  # keep `cmake --install` to just `spl`
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.17.0
  )
  FetchContent_MakeAvailable(googletest)

  add_executable(spl_tests
    tests/test_bytes.cpp
    tests/test_frame.cpp
    tests/test_pairing.cpp
    tests/test_relay.cpp
    tests/test_endpoint.cpp
    tests/test_relay_table.cpp
    tests/test_rate_limit.cpp
    tests/test_code_alloc.cpp
    tests/test_aead.cpp
    tests/test_spake2.cpp
    tests/test_wg.cpp
    tests/test_netstack.cpp
    tests/test_config.cpp
  )
  target_link_libraries(spl_tests PRIVATE spl_peer spl_crypto spl_core spl_proto spl_native GTest::gtest_main)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(spl_tests PRIVATE -Wno-macro-redefined)  # test_netstack.cpp includes lwIP
  endif()

  include(GoogleTest)
  gtest_discover_tests(spl_tests)

  # Loopback integration test: spins up `spl server` and drives all three
  # server protocols (whereami, relay, TLS pairing) over localhost.
  find_program(PYTHON3_EXECUTABLE python3)
  if(PYTHON3_EXECUTABLE)
    add_test(NAME server_integration
             COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/server_it.py $<TARGET_FILE:spl>)
    set_tests_properties(server_integration PROPERTIES TIMEOUT 60)

    # Two real `spl pair` peers rendezvous through `spl server`; checks mirrored
    # records and that a wrong SPAKE2 code aborts at key confirmation.
    add_test(NAME pairing_integration
             COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/pair_it.py $<TARGET_FILE:spl>)
    set_tests_properties(pairing_integration PROPERTIES TIMEOUT 120)

    # Full data path: pair, then run WireGuard over the relay, upgrade to a direct
    # hole-punched path, and fall back to the relay when direct is killed.
    add_test(NAME datapath_integration
             COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/data_it.py $<TARGET_FILE:spl>)
    set_tests_properties(datapath_integration PROPERTIES TIMEOUT 120)

    # Full stack: pair, then a bidirectional `spl chat` pipe through the tunnel.
    add_test(NAME daemon_integration
             COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/daemon_it.py $<TARGET_FILE:spl>)
    set_tests_properties(daemon_integration PROPERTIES TIMEOUT 120)

    add_test(NAME serve_get_integration
             COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/serve_get_it.py $<TARGET_FILE:spl>)
    set_tests_properties(serve_get_integration PROPERTIES TIMEOUT 180)

    add_test(NAME chat_integration
             COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/chat_it.py $<TARGET_FILE:spl>)
    set_tests_properties(chat_integration PROPERTIES TIMEOUT 90)

    # Stress: a large file, many pipes, and a transfer over a lossy path.
    add_test(NAME stress_integration
             COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/stress_it.py $<TARGET_FILE:spl>)
    set_tests_properties(stress_integration PROPERTIES TIMEOUT 180)

    # Onboarding: the `spl server` setup walkthrough writes a config, and a
    # config-only server then runs and relays a real pairing.
    add_test(NAME setup_integration
             COMMAND ${PYTHON3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/setup_it.py $<TARGET_FILE:spl>)
    set_tests_properties(setup_integration PROPERTIES TIMEOUT 90)
  endif()
endif()
