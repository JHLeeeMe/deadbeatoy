### src/CMakeLists.txt
###

# Sources
file(GLOB_RECURSE SRC_G
    ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

# Headers
file(GLOB_RECURSE HDR_G
    ${CMAKE_SOURCE_DIR}/include/*.h
    ${CMAKE_SOURCE_DIR}/include/*.hpp
    ${CMAKE_SOURCE_DIR}/submodules/*/include/*.h
    ${CMAKE_SOURCE_DIR}/submodules/*/include/*.hpp
)

foreach(SOURCE_FILE ${SRC_G})
    get_filename_component(SOURCE_NAME ${SOURCE_FILE} NAME_WE)

    # Create Target
    add_executable(${SOURCE_NAME}
        ${SOURCE_FILE}
        ${HDR_G}
    )

    # -I
    target_include_directories(${SOURCE_NAME}
        PUBLIC
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/submodules/BPFocket/include
            ${CMAKE_SOURCE_DIR}/submodules/IPCplusplus/include
    )

    # Set target postfix
    set_target_properties(${SOURCE_NAME}
        PROPERTIES
            DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX}
            RELWITHDEBINFO_POSTFIX ${CMAKE_RELWITHDEBINFO_POSTFIX}
    )
endforeach()
