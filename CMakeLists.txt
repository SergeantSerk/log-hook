cmake_minimum_required(VERSION 3.16)
project(vsnprintf_hook LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Option: prefer Release runtime for the release configuration
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

include(FetchContent)

# Fetch Microsoft Detours automatically
FetchContent_Declare(
  Detours
  GIT_REPOSITORY https://github.com/microsoft/Detours.git
  GIT_TAG v4.0.1
)

FetchContent_MakeAvailable(Detours)

# Custom target to build only the core Detours library (not samples)
add_custom_target(build_detours_core
    COMMAND ${CMAKE_COMMAND} -E chdir ${detours_SOURCE_DIR}/src nmake
    COMMENT "Building Microsoft Detours core library only"
    BYPRODUCTS 
        ${detours_SOURCE_DIR}/lib.X86/detours.lib
        ${detours_SOURCE_DIR}/lib.X64/detours.lib
)

# Determine architecture and set library path
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(DETOURS_LIB_DIR "${detours_SOURCE_DIR}/lib.X64")
else()
    set(DETOURS_LIB_DIR "${detours_SOURCE_DIR}/lib.X86")
endif()

# Source files
#set(HOOK_SRC src/hook_outputdebugstring.cpp) # - basic (just like a debugger)
#set(HOOK_SRC src/simple_outputdebugstring_hook.cpp) # - basic (just like a debugger)
set(HOOK_SRC src/hook_vsnprintf.cpp) # - works (extremely verbose, logs to %temp%)
#set(HOOK_SRC src/hook_format.cpp)
set(INJ_SRC src/injector.cpp) # - injector

# Hook DLL
add_library(HookDLL SHARED ${HOOK_SRC})
target_compile_definitions(HookDLL PRIVATE "HOOKDLL_EXPORTS")
target_compile_options(HookDLL PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/EHsc>)

# Link against Detours
target_link_libraries(HookDLL PRIVATE 
    ${DETOURS_LIB_DIR}/detours.lib
    kernel32
)

# Include Detours headers
target_include_directories(HookDLL PRIVATE ${detours_SOURCE_DIR}/include)

# Make sure Detours core is built before our DLL
add_dependencies(HookDLL build_detours_core)

# Injector executable
add_executable(injector ${INJ_SRC})
target_compile_options(injector PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/EHsc>)

# Link Detours for injector (needed for DetourCreateProcessWithDll)
target_link_libraries(injector PRIVATE 
    ${DETOURS_LIB_DIR}/detours.lib
    kernel32
)

# Include Detours headers for injector
target_include_directories(injector PRIVATE ${detours_SOURCE_DIR}/include)

# Make sure Detours core is built before injector
add_dependencies(injector build_detours_core)

# Installation (optional)
install(TARGETS HookDLL injector
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION bin
        ARCHIVE DESTINATION lib)
