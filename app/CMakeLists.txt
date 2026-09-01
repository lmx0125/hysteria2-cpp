file(GLOB_RECURSE HY2_APP_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
add_library(hy2_app STATIC ${HY2_APP_SOURCES})
target_include_directories(hy2_app PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(hy2_app PUBLIC hy2_core hy2_extras)

# Also build the CLI executable
file(GLOB HY2_MAIN_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp)
add_executable(hy2 ${HY2_MAIN_SOURCES})
target_link_libraries(hy2 PRIVATE hy2_app)
