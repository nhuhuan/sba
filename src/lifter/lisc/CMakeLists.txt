add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/lift.o
                   COMMAND make -j1 lift
                   COMMAND cp lift.o ${CMAKE_CURRENT_BINARY_DIR}/lift.o
                   COMMAND tar -C ${CMAKE_BINARY_DIR} -xf x86_64.tar.xz
                   COMMAND make clean
                   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                   COMMENT "Building OCaml Lifter (lisc)..."
                   VERBATIM)

add_custom_target(build_lisc_object DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/lift.o)
add_library(lisc STATIC IMPORTED GLOBAL)
set_property(TARGET lisc PROPERTY IMPORTED_LOCATION ${CMAKE_CURRENT_BINARY_DIR}/lift.o)
add_dependencies(lisc build_lisc_object)
