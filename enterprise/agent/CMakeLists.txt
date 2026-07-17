cmake_minimum_required(VERSION 3.16)
project(autosoc_agent CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# nlohmann/json (header-only) pulled at configure time.
include(FetchContent)
FetchContent_Declare(
  nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(nlohmann_json)

add_executable(autosoc-agent
  src/main.cpp
  src/process_tree.cpp
  src/anti_tamper.cpp
  src/http_client.cpp
  src/isolation.cpp
)

# HTTP transport is implemented on raw BSD/Winsock2 sockets (see
# src/http_client.cpp) — no libcurl dependency, keeping the agent lightweight.
target_link_libraries(autosoc-agent PRIVATE nlohmann_json::nlohmann_json)

if(WIN32)
  target_link_libraries(autosoc-agent PRIVATE advapi32 ws2_32)
else()
  find_package(Threads REQUIRED)
  target_link_libraries(autosoc-agent PRIVATE Threads::Threads)
endif()

# Build:  cmake -B build && cmake --build build -j
# Run:    AUTOSOC_SERVERS=http://primary:8000,http://backup:8000 \
#         AUTOSOC_ENROLLMENT_TOKEN=enr-... sudo ./build/autosoc-agent
# Test:   ... sudo ./build/autosoc-agent --once   (single enroll+heartbeat cycle)
