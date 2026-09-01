file(GLOB_RECURSE HY2_CORE_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
add_library(hy2_core STATIC ${HY2_CORE_SOURCES})
target_include_directories(hy2_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(hy2_core PUBLIC cxx_std_20)

find_package(Threads REQUIRED)
target_link_libraries(hy2_core PUBLIC Threads::Threads)
