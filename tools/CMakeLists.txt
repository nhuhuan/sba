find_library(OCAML_STR_LIB NAMES str str.a PATHS ${OCAML_LIB_PATH} ${OCAML_LIB_PATH}/str NO_DEFAULT_PATH)
find_library(OCAML_STR_STUB_LIB NAMES camlstr camlstrnat camlstrnat.a libcamlstr.a PATHS ${OCAML_LIB_PATH} ${OCAML_LIB_PATH}/stublibs NO_DEFAULT_PATH)
find_library(OCAML_RUNTIME_LIB NAMES asmrun libasmrun.a PATHS ${OCAML_LIB_PATH} NO_DEFAULT_PATH)

add_subdirectory(jump_table)
