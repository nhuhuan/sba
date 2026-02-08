cmake_minimum_required(VERSION 3.28 FATAL_ERROR)

project(SBA
	DESCRIPTION "Static Binary Analysis Framework"
	LANGUAGES CXX C
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)

enable_testing()

find_package(LLVM REQUIRED CONFIG COMPONENTS
	mc
	mcdisassembler
	object
	support
	X86
	AArch64
)

llvm_map_components_to_libnames(llvm_libs
	mc
	mcdisassembler
	object
	support
	X86
	AArch64
)

add_subdirectory(src/analysis)
add_subdirectory(tools)
