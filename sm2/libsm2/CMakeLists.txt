
# 请严格遵守此文件命令编写顺序，否则将无法编译
#指定输出文件目录
SET(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

INCLUDE_DIRECTORIES(./ /usr/local/opt/openssl/include /usr/local/include /usr/include)

#指定连接库搜索路径
LINK_DIRECTORIES(/usr/lib /usr/local/lib ${PROJECT_SOURCE_DIR}/lib /usr/local/opt/openssl/lib)

#指定源文件
set(TEST_SOURCE_FILES sm2test.c)
set(LIB_SOURCE_FILES sm2.c)

#指定链接库
LINK_LIBRARIES(ssl crypto)
#指定输出动态库
ADD_LIBRARY(sm2 SHARED ${LIB_SOURCE_FILES})         # 生成静态链接库libsm2.so

#指定链接库
LINK_LIBRARIES(sm2)

#指定输出可执行文件
ADD_EXECUTABLE(sm2test ${TEST_SOURCE_FILES})