add_library(binary)

target_sources(binary
	PUBLIC
		FILE_SET modules TYPE CXX_MODULES
			BASE_DIRS ${CMAKE_SOURCE_DIR}/modules
			FILES
				${CMAKE_SOURCE_DIR}/modules/binary/types.cppm
				${CMAKE_SOURCE_DIR}/modules/binary/object.cppm
				${CMAKE_SOURCE_DIR}/modules/binary/elf.cppm
				${CMAKE_SOURCE_DIR}/modules/binary/error.cppm
				${CMAKE_SOURCE_DIR}/modules/binary/binary.cppm
	PRIVATE
		types.cpp
		object.cpp
		elf.cpp
)

target_include_directories(binary PRIVATE ${LLVM_INCLUDE_DIRS})
target_compile_definitions(binary PRIVATE ${LLVM_DEFINITIONS})
target_link_libraries(binary
	PRIVATE
		${llvm_libs}
)
