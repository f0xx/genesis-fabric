cmake_minimum_required(VERSION 3.16)
project(genesis VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

option(GENESIS_NATIVE_ARCH "Pass -march=native (off so binaries can be copied to other hosts)" OFF)
set(GENESIS_SANITIZER "" CACHE STRING "address, undefined, thread, or leak. One at a time.")
set(GENESIS_IO_URING "AUTO" CACHE STRING "AUTO, ON, or OFF")

add_compile_options(-Wall -Wextra -Werror -Wformat=2 -D_FILE_OFFSET_BITS=64)
if(GENESIS_NATIVE_ARCH)
    add_compile_options(-march=native)
endif()

if(GENESIS_SANITIZER STREQUAL "address")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g)
    add_link_options(-fsanitize=address,undefined)
elseif(GENESIS_SANITIZER STREQUAL "undefined")
    add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer -O1 -g)
    add_link_options(-fsanitize=undefined)
elseif(GENESIS_SANITIZER STREQUAL "thread")
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -O1 -g)
    add_link_options(-fsanitize=thread)
elseif(GENESIS_SANITIZER STREQUAL "leak")
    add_compile_options(-fsanitize=leak -fno-omit-frame-pointer -O1 -g)
    add_link_options(-fsanitize=leak)
elseif(NOT GENESIS_SANITIZER STREQUAL "")
    message(FATAL_ERROR "GENESIS_SANITIZER must be address, undefined, thread, leak, or empty")
endif()

set(GENESIS_HAS_IO_URING 0)
if(NOT GENESIS_IO_URING STREQUAL "OFF")
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBURING liburing)
    endif()
    if(LIBURING_FOUND)
        set(GENESIS_HAS_IO_URING 1)
    elseif(GENESIS_IO_URING STREQUAL "ON")
        message(FATAL_ERROR "io_uring requested but liburing was not found")
    endif()
endif()

set(GENESIS_CORE_SOURCES
    src/core/aead.cpp
    src/core/bbr.cpp
    src/core/config.cpp
    src/core/dht.cpp
    src/core/discovery.cpp
    src/core/engine.cpp
    src/core/fec.cpp
    src/core/handshake.cpp
    src/core/hkdf.cpp
    src/core/log.cpp
    src/core/md5.cpp
    src/core/mesh.cpp
    src/core/sha1.cpp
    src/core/sha256.cpp
    src/core/stun.cpp
    src/core/vfs_codec.cpp
    src/core/wire.cpp
    src/core/x25519.cpp
    src/posix/api.cpp
    src/posix/jail.cpp
    src/posix/random.cpp
    src/posix/session.cpp
    src/posix/control.cpp
    src/posix/udp.cpp
    src/posix/vfs.cpp
)

add_library(genesis_core SHARED ${GENESIS_CORE_SOURCES})
target_include_directories(genesis_core
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
           $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/core ${CMAKE_CURRENT_SOURCE_DIR}/src/posix)
target_compile_definitions(genesis_core PRIVATE GENESIS_HAS_IO_URING=${GENESIS_HAS_IO_URING})
target_link_libraries(genesis_core PUBLIC pthread)
if(GENESIS_HAS_IO_URING)
    target_include_directories(genesis_core PRIVATE ${LIBURING_INCLUDE_DIRS})
    target_link_libraries(genesis_core PRIVATE ${LIBURING_LIBRARIES})
endif()
set_target_properties(genesis_core PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})

add_library(genesis_core_embedded STATIC
    src/core/aead.cpp
    src/core/bbr.cpp
    src/core/dht.cpp
    src/core/discovery.cpp
    src/core/engine.cpp
    src/core/fec.cpp
    src/core/handshake.cpp
    src/core/hkdf.cpp
    src/core/log.cpp
    src/core/md5.cpp
    src/core/mesh.cpp
    src/core/sha1.cpp
    src/core/sha256.cpp
    src/core/stun.cpp
    src/core/wire.cpp
    src/core/x25519.cpp
    src/embedded/random_stub.cpp
)
target_include_directories(genesis_core_embedded PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/core ${CMAKE_CURRENT_SOURCE_DIR}/src/embedded)
target_compile_definitions(genesis_core_embedded PUBLIC GENESIS_EMBEDDED=1)

add_executable(genesis apps/cli/main.cpp)
target_include_directories(genesis PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/core)
target_link_libraries(genesis PRIVATE genesis_core)

add_executable(genesisd apps/daemon/main.cpp)
target_link_libraries(genesisd PRIVATE genesis_core)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(FUSE3 fuse3)
endif()
if(FUSE3_FOUND)
    add_executable(mount_genesis apps/mount/main.cpp)
    target_compile_definitions(mount_genesis PRIVATE FUSE_USE_VERSION=35)
    target_include_directories(mount_genesis PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/core ${FUSE3_INCLUDE_DIRS})
    target_link_libraries(mount_genesis PRIVATE genesis_core ${FUSE3_LIBRARIES})
    set_target_properties(mount_genesis PROPERTIES OUTPUT_NAME mount.genesis)
endif()

add_executable(genesis_tests tests/test_main.cpp)
target_include_directories(genesis_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/core ${CMAKE_CURRENT_SOURCE_DIR}/src/posix)
target_link_libraries(genesis_tests PRIVATE genesis_core)

add_executable(genesis-perf tools/perf.cpp)
target_include_directories(genesis-perf PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/core)
target_link_libraries(genesis-perf PRIVATE genesis_core)

enable_testing()
add_test(NAME unit COMMAND genesis_tests)
set_tests_properties(unit PROPERTIES WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} TIMEOUT 180)
if(GENESIS_SANITIZER STREQUAL "")
    add_test(NAME perf COMMAND genesis-perf)
    set_tests_properties(perf PROPERTIES TIMEOUT 120)
endif()

include(GNUInstallDirs)
install(TARGETS genesis_core genesis genesisd
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(TARGET mount_genesis)
    install(TARGETS mount_genesis RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
install(FILES include/genesis/api.h include/genesis/client.hpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/genesis)
install(FILES packaging/systemd/genesisd.service DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system)
install(FILES packaging/openrc/genesisd DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/init.d)
install(FILES config/genesis.conf.example DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/genesis)
