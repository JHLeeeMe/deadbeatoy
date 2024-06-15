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

foreach(SRC ${SRC_G})
    get_filename_component(SRC_NAME ${SRC} NAME_WE)

    if(NOT ${SRC_NAME} MATCHES ".*_main$")
        continue()
    endif()

    string(REGEX REPLACE "_main$" "" BASE_NAME ${SRC_NAME})
    set(RELATED_SRC "${CMAKE_CURRENT_SOURCE_DIR}/${BASE_NAME}.cpp")

    set(SRC_LIST ${SRC})
    if(EXISTS ${RELATED_SRC})
        list(APPEND SRC_LIST ${RELATED_SRC})
    endif()

    # Create Target
    add_executable(${SRC_NAME}
        ${SRC_LIST}
        ${HDR_G}
    )

    # -I
    target_include_directories(${SRC_NAME}
        PUBLIC
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/submodules/BPFocket/include
            ${CMAKE_SOURCE_DIR}/submodules/IPCplusplus/include
    )

    # Set target postfix
    set_target_properties(${SRC_NAME}
        PROPERTIES
            DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX}
            RELWITHDEBINFO_POSTFIX ${CMAKE_RELWITHDEBINFO_POSTFIX}
    )
endforeach()
