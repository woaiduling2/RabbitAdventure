project(RabbitAdventure)

# 设置库文件的输出目录,用双引号括起来的这个路径不会在外面套一层Debug或Release
# 动态库输出目录
SET( CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_HOME_DIRECTORY}/Bin/")
SET( CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_HOME_DIRECTORY}/Bin/")
SET( CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_HOME_DIRECTORY}/Bin/")
SET( CMAKE_RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_HOME_DIRECTORY}/Bin/")
# 静态库输出目录
SET( CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_HOME_DIRECTORY}/Lib/${PROJECT_NAME}")
SET( CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_HOME_DIRECTORY}/Lib/${PROJECT_NAME}")
SET( CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_HOME_DIRECTORY}/Lib/${PROJECT_NAME}")
SET( CMAKE_ARCHIVE_OUTPUT_DIRECTORY_MINSIZEREL "${CMAKE_HOME_DIRECTORY}/Lib/${PROJECT_NAME}")


# 设置版本号
set(MY_VERSIONINFO_RC "${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}.rc")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}.rc.in"
    "${MY_VERSIONINFO_RC}"
)

#查找当前目录下的所有源文件将名称保存到Header变量和Source变量
aux_source_directory(Source/ Source)
# 遍历所有路径下的头文件,加到变量Header里
file(GLOB_RECURSE Header "Header/*.h")

#启动对C++20标准的支持
set(CMAKE_CXX_STANDARD 20)
# 启动对C11标准的支持,这玩意怎么不起作用的?
set(CMAKE_C_STANDARD 11)

add_executable(${PROJECT_NAME} 
    ${Header}
    ${Source}
    "${MY_VERSIONINFO_RC}"
)
#add_library(sub::lib2 ALIAS ${PROJECT_NAME})

# 附加包含目录
target_include_directories(${PROJECT_NAME} 
    PRIVATE
     "${CMAKE_SOURCE_DIR}/OpenCV3.4.1_64/include" 
     "${CMAKE_SOURCE_DIR}/zlib1.2.13_64/include" 
)

file(GLOB_RECURSE LIBRARY_debug 
    "${CMAKE_SOURCE_DIR}/Lib/OpenCV3.4.1_64/opencv_world341d.lib"
    "${CMAKE_SOURCE_DIR}/Lib/zlib1.2.13_64/zlibd.lib"
)
file(GLOB_RECURSE LIBRARY_release 
    "${CMAKE_SOURCE_DIR}/Lib/OpenCV3.4.1_64/opencv_world341.lib"
	"${CMAKE_SOURCE_DIR}/Lib/zlib1.2.13_64/zlib.lib"
)

#生成器表达式的调试信息会输出到文件
#file(GENERATE OUTPUT "$<IF:$<CONFIG:Release>,eBillWinApirelease_config,eBillWinApidebug_config>.txt" CONTENT "$<IF:$<CONFIG:Release>,${LIBRARY_release},${LIBRARY_debug}>")

# 引入自己的库
target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
	"$<IF:$<CONFIG:Release>,${LIBRARY_release},${LIBRARY_debug}>"
)

# 设置预处理器,导出库
#add_definitions("-DLIB_EXPORTS")
# 设置UNICODE编码
add_definitions(-DUNICODE -D_UNICODE)
add_definitions(-DZLIB_CONST)

# 给dll添加后缀,标识是release不是debug库
set_target_properties(${PROJECT_NAME} PROPERTIES DEBUG_POSTFIX "_d") 
set_target_properties(${PROJECT_NAME} PROPERTIES RELEASE_POSTFIX "_r") 
set_target_properties(${PROJECT_NAME} PROPERTIES RELWITHDEBINFO_POSTFIX "_r") 
set_target_properties(${PROJECT_NAME} PROPERTIES MINSIZEREL_POSTFIX "_r") 

# 安装库到运行目录Bin里去
install (TARGETS ${PROJECT_NAME}
 DESTINATION .)

 source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES  
    ${Header}
    ${Source}
)

# 编译前
add_custom_command(TARGET ${PROJECT_NAME} 
   PRE_BUILD 
   COMMAND ("${CMAKE_COMMAND}" -E rm -rf "${CMAKE_HOME_DIRECTORY}/Bin/opencv_world341.dll" "${CMAKE_HOME_DIRECTORY}/Bin/opencv_world341d.dll" "${CMAKE_HOME_DIRECTORY}/Bin/zlib.dll" "${CMAKE_HOME_DIRECTORY}/Bin/zlibd.dll")
   COMMAND "${CMAKE_COMMAND}" -E  copy ${CMAKE_SOURCE_DIR}/OpenCV3.4.1_64/opencv_world341.dll ${CMAKE_SOURCE_DIR}/Bin/
   COMMAND "${CMAKE_COMMAND}" -E  copy ${CMAKE_SOURCE_DIR}/OpenCV3.4.1_64/opencv_world341d.dll ${CMAKE_SOURCE_DIR}/Bin/
   COMMAND "${CMAKE_COMMAND}" -E  copy ${CMAKE_SOURCE_DIR}/zlib1.2.13_64/zlib.dll ${CMAKE_SOURCE_DIR}/Bin/
   COMMAND "${CMAKE_COMMAND}" -E  copy ${CMAKE_SOURCE_DIR}/zlib1.2.13_64/zlibd.dll ${CMAKE_SOURCE_DIR}/Bin/
   COMMENT "replace opencv dlls"
)

