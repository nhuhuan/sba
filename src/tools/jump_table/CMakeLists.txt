add_executable(jump_table jump_table.cpp)

find_library(OCAML_STR_LIB
    NAMES str str.a
    PATHS ${OCAML_LIB_PATH} ${OCAML_LIB_PATH}/str
    NO_DEFAULT_PATH
)

find_library(OCAML_STR_STUB_LIB
    NAMES camlstr camlstrnat camlstrnat.a libcamlstr.a
    PATHS ${OCAML_LIB_PATH} ${OCAML_LIB_PATH}/stublibs
    NO_DEFAULT_PATH
)

target_link_libraries(jump_table PRIVATE 
    sba 
    lisc 
    asmrun_shared 
    ${OCAML_STR_LIB} 
    ${OCAML_STR_STUB_LIB}
)

target_link_directories(jump_table PRIVATE ${OCAML_LIB_PATH})
target_include_directories(jump_table PRIVATE ${OCAML_LIB_PATH})
