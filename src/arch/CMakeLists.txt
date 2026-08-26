add_library(arch)

target_sources(arch
	PUBLIC
		FILE_SET modules TYPE CXX_MODULES
			BASE_DIRS ${CMAKE_SOURCE_DIR}/modules
			FILES
				${CMAKE_SOURCE_DIR}/modules/arch/x86_64.cppm
				${CMAKE_SOURCE_DIR}/modules/arch/arch.cppm
)
