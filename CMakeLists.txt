cmake_minimum_required(VERSION 3.16.0 FATAL_ERROR)

project(SBA VERSION 1.0
            DESCRIPTION "Static Binary Analysis Framework"
            LANGUAGES CXX)

add_custom_command(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/lift/lift.o
                   COMMAND make
                   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lift
                   COMMENT "Compile binary lifter ..."
                   VERBATIM)

add_executable(jump_table analysis/jump_table.cpp
               sba/framework.cpp sba/program.cpp sba/function.cpp sba/scc.cpp
               sba/block.cpp sba/insn.cpp sba/state.cpp sba/domain.cpp
               sba/rtl.cpp sba/expr.cpp sba/parser.cpp sba/system.cpp
               sba/type.cpp sba/common.cpp lift/lift.o)

target_compile_features(jump_table PRIVATE cxx_std_20)
target_link_directories(jump_table PRIVATE /usr/lib/ocaml/)
target_link_libraries(jump_table PRIVATE asmrun_shared camlstr)
