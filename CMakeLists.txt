cmake_minimum_required(VERSION 3.16.0 FATAL_ERROR)

project(SBA VERSION 1.0
            DESCRIPTION "Static Binary Analysis Framework"
            LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)

execute_process(
    COMMAND ocamlc -where
    OUTPUT_VARIABLE OCAML_LIB_PATH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

add_subdirectory(src/lifter/lisc)
add_subdirectory(src/sba)
add_subdirectory(src/tools/jump_table)
