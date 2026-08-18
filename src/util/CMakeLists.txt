add_library(util)

target_sources(util
	PUBLIC
		FILE_SET modules TYPE CXX_MODULES
			BASE_DIRS ${CMAKE_SOURCE_DIR}/modules
			FILES
				${CMAKE_SOURCE_DIR}/modules/util/container.cppm
				${CMAKE_SOURCE_DIR}/modules/util/wyhash.cppm
)
