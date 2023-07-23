cmake_minimum_required(VERSION 3.7.14)
project(ClickMe)
set(CMAKE_BUILD_TYPE "Debug")
# set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_CONFIGURATION_TYPES "Debug;Release")
# 设置目标生成路径
set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR}/Bin)

# 设置build目录为code目录
#set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/Code")

# 为了根据编译日期生成版本号加的年月日变量
string(TIMESTAMP COMPILE_VERSION_YEAR %Y)
string(TIMESTAMP COMPILE_VERSION_MONTH %m)
string(TIMESTAMP COMPILE_VERSION_DAY %d)
string(TIMESTAMP COMPILE_VERSION_HOUR %H)

#打开允许创建文件夹的开关
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
#给 cmake 自动创建的工程重新命名, 默认名为 "CMakePredefinedTargets" 
set_property(GLOBAL PROPERTY PREDEFINED_TARGETS_FOLDER "CMakeGen")
#把工程加到文件夹中
#set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "CMakeGen")

# 添加C++项目
add_subdirectory(${PROJECT_SOURCE_DIR}/RabbitAdventure)
