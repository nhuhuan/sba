add_library(sba
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

target_include_directories(sba PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_include_directories(sba PRIVATE ${OCAML_LIB_PATH})
