add_library(analysis
	util/common.cpp
	core/framework.cpp
	core/domain.cpp
	core/state.cpp
	arch/x86_64.cpp
	ir/rtl.cpp
	ir/expr.cpp
	ir/type.cpp
	ir/parser.cpp
	cfg/intra/program.cpp
	cfg/intra/function.cpp
	cfg/intra/block.cpp
	cfg/intra/insn.cpp
	cfg/intra/scc.cpp
)

target_include_directories(analysis PUBLIC
	${CMAKE_SOURCE_DIR}/include
)

target_include_directories(analysis PRIVATE
	${OCAML_LIB_PATH}
)

add_subdirectory(lift)
