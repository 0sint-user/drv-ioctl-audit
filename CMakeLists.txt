cmake_minimum_required(VERSION 3.20)
project(drv_ioctl_audit VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(drv_audit_core STATIC
    src/pe_parser.cpp
    src/ioctl_audit.cpp
)
target_include_directories(drv_audit_core PUBLIC include)
if(MSVC)
    target_compile_options(drv_audit_core PRIVATE /W4 /WX)
else()
    target_compile_options(drv_audit_core PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

add_executable(drv-ioctl-audit src/main.cpp)
target_link_libraries(drv-ioctl-audit PRIVATE drv_audit_core)

enable_testing()
add_executable(test_audit tests/test_audit.cpp)
target_link_libraries(test_audit PRIVATE drv_audit_core)
add_test(NAME test_audit COMMAND test_audit)
