cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Header files location
include_directories(${CMAKE_SOURCE_DIR}/include)

# Common source files shared by all versions
set(COMMON_SOURCES
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

# Version 1: Basic packet analyzer
add_executable(packet_analyzer
    src/main.cpp
    ${COMMON_SOURCES}
)

# Version 2: Simple DPI with SNI + blocking
add_executable(dpi_simple
    src/main_working.cpp
    ${COMMON_SOURCES}
)

# Version 3: Full multi-threaded DPI engine
add_executable(dpi_engine
    src/dpi_mt.cpp
    ${COMMON_SOURCES}
)

# Link threading library for multi-threaded version
find_package(Threads REQUIRED)
target_link_libraries(dpi_engine Threads::Threads)

# Version 4: Full DPI engine with separate components
add_executable(dpi_full
    src/main_dpi.cpp
    src/dpi_engine.cpp
    src/load_balancer.cpp
    src/fast_path.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)
target_link_libraries(dpi_full Threads::Threads)

if(APPLE)
    # macOS specific settings
endif()