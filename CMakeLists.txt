cmake_minimum_required(VERSION 3.22.1)
project(tink-tcl VERSION 2.0.0 LANGUAGES CXX C)
message(project: ${PROJECT_NAME})

set(TARGET ${PROJECT_NAME})
set(CMAKE_C_STANDARD   11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED true)
set(CMAKE_C_STANDARD_REQUIRED true)
set(THREADS_PREFER_PTHREAD_FLAG ON)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(BUILD_SHARED_LIBS ON)
find_package(Threads REQUIRED)

#set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_FLAGS "-DTCL_THREADS -DPROJECT_VERSION=${PROJECT_VERSION} ${CMAKE_CXX_FLAGS} -L${CMAKE_INSTALL_PREFIX}/lib")

add_library(tink-tcl MODULE
        src/awskms/aws_kms_aead.h
        src/awskms/aws_kms_client.h
        src/library.cc
        src/awskms/aws_kms_aead.cc
        src/awskms/aws_kms_client.cc
)
set_target_properties(tink-tcl PROPERTIES POSITION_INDEPENDENT_CODE ON)
include_directories("${CMAKE_INSTALL_PREFIX}/include" ${TCL_INCLUDE_PATH})
link_directories(tink-tcl "${CMAKE_INSTALL_PREFIX}/lib" ${TCL_LIBRARY_PATH})
target_link_libraries(tink-tcl PRIVATE tink absl_strings absl_synchronization absl_status protobuf protobuf-lite aws-cpp-sdk-core aws-cpp-sdk-kms)

install(TARGETS ${TARGET}
        LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${TARGET}${PROJECT_VERSION}
)

configure_file(pkgIndex.tcl.in pkgIndex.tcl @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgIndex.tcl
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${TARGET}${PROJECT_VERSION}
)