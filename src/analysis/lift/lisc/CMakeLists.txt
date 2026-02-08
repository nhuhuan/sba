execute_process(
	COMMAND ocamlc -where
	OUTPUT_VARIABLE OCAML_LIB_PATH
	OUTPUT_STRIP_TRAILING_WHITESPACE
)

set(OCAML_LIB_PATH ${OCAML_LIB_PATH} CACHE INTERNAL "OCaml library path")

set(LISC_SRC
	Makefile
	learn.ml learn.mli lexAsm.mll lexRtl.mll main.ml
	parseARM.mly parseATT.mly parseAVR.mly parseITC.mly parseRtl.mly
	sa.ml x86_64.tar.xz
)

set(LISC_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/build")
file(MAKE_DIRECTORY ${LISC_BUILD_DIR})
find_program(MAKE make REQUIRED)

set(LISC_COPIES "")
foreach(f ${LISC_SRC})
	set(src "${CMAKE_CURRENT_SOURCE_DIR}/${f}")
	set(dst "${LISC_BUILD_DIR}/${f}")
	add_custom_command(OUTPUT "${dst}"
		COMMAND ${CMAKE_COMMAND} -E copy_if_different "${src}" "${dst}"
		DEPENDS "${src}"
		VERBATIM
	)
    list(APPEND LISC_COPIES "${dst}")
endforeach()

add_custom_command(
	OUTPUT "${LISC_BUILD_DIR}/lift.o"
	COMMAND ${MAKE} -C "${LISC_BUILD_DIR}" -j1 lift
	COMMAND tar -C "${CMAKE_BINARY_DIR}" -xf "${LISC_BUILD_DIR}/x86_64.tar.xz"
	DEPENDS ${LISC_COPIES}
	COMMENT "Building OCaml Lifter (lisc) in ${LISC_BUILD_DIR}..."
	VERBATIM
)

add_custom_target(lisc_object DEPENDS "${LISC_BUILD_DIR}/lift.o")
add_library(lisc STATIC IMPORTED GLOBAL)
set_property(TARGET lisc PROPERTY IMPORTED_LOCATION "${LISC_BUILD_DIR}/lift.o")
add_dependencies(lisc lisc_object)
