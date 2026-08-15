add_library(lift)

target_sources(lift
	PUBLIC
		FILE_SET modules TYPE CXX_MODULES
			BASE_DIRS ${CMAKE_SOURCE_DIR}/modules
			FILES
				${CMAKE_SOURCE_DIR}/modules/lift/dedup.cppm
				${CMAKE_SOURCE_DIR}/modules/lift/decoder.cppm
				${CMAKE_SOURCE_DIR}/modules/lift/parse.cppm
				${CMAKE_SOURCE_DIR}/modules/lift/lift.cppm
	PRIVATE
		dedup.cpp
		decoder.cpp
		x86_64.cpp
)

target_link_libraries(lift
	PUBLIC
		arch
		ir
		binary
		util
		${llvm_libs}
)
