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
    ${CMAKE_SOURCE_DIR}/submodules/BPFocket/include/*.h
    ${CMAKE_SOURCE_DIR}/submodules/BPFocket/include/*.hpp
    ${CMAKE_SOURCE_DIR}/submodules/IPCplusplus/include/*.h
    ${CMAKE_SOURCE_DIR}/submodules/IPCplusplus/include/*.hpp
)

# Create Target
add_executable(Main
    ${SRC_G}
    ${HDR_G}
)

# Set target postfix
set_target_properties(Main
    PROPERTIES
        DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX}
        RELWITHDEBINFO_POSTFIX ${CMAKE_RELWITHDEBINFO_POSTFIX}
)

# -I
target_include_directories(Main
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/submodules/BPFocket/include
        ${CMAKE_SOURCE_DIR}/submodules/IPCplusplus/include
)
