add_library(ir)

target_sources(ir
	PUBLIC
		FILE_SET modules TYPE CXX_MODULES
			BASE_DIRS ${CMAKE_SOURCE_DIR}/modules
			FILES
				${CMAKE_SOURCE_DIR}/modules/ir/syntax.cppm
				${CMAKE_SOURCE_DIR}/modules/ir/constant.cppm
				${CMAKE_SOURCE_DIR}/modules/ir/context.cppm
				${CMAKE_SOURCE_DIR}/modules/ir/semantics.cppm
				${CMAKE_SOURCE_DIR}/modules/ir/view.cppm
				${CMAKE_SOURCE_DIR}/modules/ir/ir.cppm
)

target_link_libraries(ir PUBLIC util)
