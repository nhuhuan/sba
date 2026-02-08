add_executable(jump_table jump_table.cpp)

target_link_libraries(jump_table PRIVATE
	analysis
	lisc
	${OCAML_RUNTIME_LIB}
	${OCAML_STR_LIB}
	${OCAML_STR_STUB_LIB}
)

target_include_directories(jump_table PRIVATE
	${OCAML_LIB_PATH}
)
