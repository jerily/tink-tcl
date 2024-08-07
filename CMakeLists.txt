cmake_minimum_required(VERSION 3.22.1)
project(tink-tcl VERSION 20240704.0.0 LANGUAGES CXX C)
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

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(Threads REQUIRED)
find_package (PkgConfig REQUIRED)
pkg_check_modules (ABSL REQUIRED absl_status absl_statusor absl_synchronization absl_strings absl_hash absl_raw_hash_set) # ABSL_INCLUDE_DIRS, ABSL_LIBRARIES, ABSL_LIBRARY_DIRS
pkg_check_modules (PROTOBUF REQUIRED protobuf) # PROTOBUF_INCLUDE_DIRS, PROTOBUF_LIBRARIES, PROTOBUF_LIBRARY_DIRS
find_package(TCL 8.6.13 REQUIRED)  # TCL_INCLUDE_PATH TCL_LIBRARY

message(STATUS "TCL_INCLUDE_PATH: ${TCL_INCLUDE_PATH}")
message(STATUS "TCL_LIBRARY: ${TCL_LIBRARY}")
message(STATUS "ABSL_INCLUDE_DIRS: ${ABSL_INCLUDE_DIRS}")
message(STATUS "ABSL_LIBRARIES: ${ABSL_LIBRARIES}")
message(STATUS "ABSL_LIBRARY_DIRS: ${ABSL_LIBRARY_DIRS}")
message(STATUS "PROTOBUF_FOUND: ${PROTOBUF_FOUND}")
message(STATUS "PROTOBUF_INCLUDE_DIRS: ${PROTOBUF_INCLUDE_DIRS}")
message(STATUS "PROTOBUF_LIBRARIES: ${PROTOBUF_LIBRARIES}")
message(STATUS "PROTOBUF_LIBRARY_DIRS: ${PROTOBUF_LIBRARY_DIRS}")

#set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_FLAGS "-DTCL_THREADS -DPROJECT_VERSION=${PROJECT_VERSION} ${CMAKE_CXX_FLAGS}")

add_library(tink-tcl SHARED
        src/library.cc
)

set_target_properties(tink-tcl PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        INSTALL_RPATH_USE_LINK_PATH ON
)
get_filename_component(TCL_LIBRARY_PATH "${TCL_LIBRARY}" PATH)
include_directories(${TCL_INCLUDE_PATH} ${ABSL_INCLUDE_DIRS} ${PROTOBUF_INCLUDE_DIRS})
link_directories(tink-tcl ${TCL_LIBRARY_PATH} ${ABSL_LIBRARY_DIRS} ${PROTOBUF_LIBRARY_DIRS})
target_link_directories(tink-tcl PRIVATE ${TCL_LIBRARY_PATH} ${ABSL_LIBRARY_DIRS} ${PROTOBUF_LIBRARY_DIRS} ${TINK_CPP_DIR}/lib)
target_link_libraries(tink-tcl PRIVATE tink ${TCL_LIBRARY} ${ABSL_LIBRARIES} ${PROTOBUF_LIBRARIES})

install(TARGETS ${TARGET}
        LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${TARGET}${PROJECT_VERSION}
)

configure_file(pkgIndex.tcl.in pkgIndex.tcl @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgIndex.tcl
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/${TARGET}${PROJECT_VERSION}
)
