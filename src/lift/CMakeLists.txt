add_library(lift)

target_sources(lift
	PUBLIC
		FILE_SET modules TYPE CXX_MODULES
			BASE_DIRS ${CMAKE_SOURCE_DIR}/modules
			FILES
				${CMAKE_SOURCE_DIR}/modules/lift/cache.cppm
				${CMAKE_SOURCE_DIR}/modules/lift/target.cppm
				${CMAKE_SOURCE_DIR}/modules/lift/decoder.cppm
				${CMAKE_SOURCE_DIR}/modules/lift/parser.cppm
				${CMAKE_SOURCE_DIR}/modules/lift/emit.cppm
				${CMAKE_SOURCE_DIR}/modules/lift/fallback.cppm
				${CMAKE_SOURCE_DIR}/modules/lift/lift.cppm
	PRIVATE
		decoder.cpp
		x86_64/extract.cpp
		x86_64/lift.cpp
)

target_link_libraries(lift
	PUBLIC
		arch
		ir
		binary
		util
		${llvm_libs}
)
