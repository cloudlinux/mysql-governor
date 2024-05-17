CMAKE_MINIMUM_REQUIRED(VERSION 2.4)

PROJECT(MYSQL_GOVERNOR C)

INCLUDE(CheckFunctionExists)

CHECK_FUNCTION_EXISTS (mmap64 HAVE_MMAP64)

SET(CMAKE_BUILD_TYPE Debug)
SET(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
#SET(MYSQL_INCLUDE_DIRS "/usr/include/mysql")
FIND_PACKAGE(GLIB2 REQUIRED)
FIND_PACKAGE(LibXml2 REQUIRED)
#FIND_PACKAGE(MySQL REQUIRED)

#INCLUDE_DIRECTORIES(${GLIB2_INCLUDE_DIRS} ${MYSQL_INCLUDE_DIRS})
INCLUDE_DIRECTORIES(${GLIB2_INCLUDE_DIRS})
INCLUDE_DIRECTORIES(${LIBXML2_INCLUDE_DIR})
#LINK_LIBRARIES(${GLIB2_LIBRARIES} ${MYSQL_CLIENT_LIBS})
#INCLUDE_DIRECTORIES(${GLIB2_INCLUDE_DIRS})
SET(LIBS ${GLIB2_LIBRARIES} ${LIBXML2_LIBRARIES} pthread m rt dl ncurses)
# TODO: Add cl-sentry and sentry to the list of libraries when sentry-native package will be available for all platforms

IF (${SYSTEMD_FLAG})
	add_definitions(-DSYSTEMD_FLAG=1)
	SET(LIBS ${LIBS} systemd)
ENDIF(${SYSTEMD_FLAG})

IF (${TEST})
	add_definitions(-DTEST=1)
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0")
	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")
	set(CMAKE_CXX_FLAGS_DEBUG "-g")
ENDIF(${TEST})

SET(EXECUTABLE_OUTPUT_PATH "bin")
SET(LIBRARY_OUTPUT_PATH "lib")

SET(SRC "${CMAKE_SOURCE_DIR}/src/")
SET(config_SRC ${SRC}/governor_config.c ${SRC}/xml.c)
SET(db_governor_SRC ${SRC}/governor.c
					${config_SRC}
					${SRC}/fifo_stats.c
					${SRC}/stats.c
					${SRC}/user_account.c
					${SRC}/dbgovernor_string_functions.c
					${SRC}/log.c
					${SRC}/wrappers.c
					${SRC}/dlload.c
					${SRC}/calc_stats.c
					${SRC}/governor_server.c
					${SRC}/parce_proc_fs.c
					${SRC}/tick_generator.c
					${SRC}/tid_table.c
					${SRC}/mysql_connector_common.c
					${SRC}/log-decoder.c
					${SRC}/getsysinfo.c
					${SRC}/commands.c
					${SRC}/dbtop_server.c
					${SRC}/shared_memory.c
					${SRC}/dbuser_map.c
					${SRC}/slow_queries.c
)
SET(dbtop_SRC ${SRC}/dbtop.c ${SRC}/dbgovernor_string_functions.c ${SRC}/wrappers.c)
SET(mysql_unfreeze_SRC ${SRC}/mysql_unfreeze.c
					${SRC}/wrappers.c ${SRC}/mysql_connector_common.c
					${SRC}/dbgovernor_string_functions.c
					${SRC}/dlload.c
					${SRC}/log.c
					${config_SRC}
					${SRC}/shared_memory.c
					${SRC}/calc_stats.c
					${SRC}/user_account.c
					${SRC}/stats.c
					${SRC}/fifo_stats.c
					${SRC}/tick_generator.c
					${SRC}/tid_table.c
					${SRC}/log-decoder.c
					${SRC}/getsysinfo.c
					${SRC}/commands.c
					${SRC}/dbuser_map.c
)
SET(dbctl_SRC ${SRC}/dbctl.c
					${SRC}/dbctl_set.c
					${SRC}/dbctl_list.c
					${SRC}/dbctl_rest.c
					${SRC}/dbctl_conn.c
					${SRC}/dbctl_cfg.c
					
					${SRC}/shared_memory.c
					${SRC}/log.c
					${SRC}/dlload.c
					${SRC}/wrappers.c
					${SRC}/dbgovernor_string_functions.c
					${SRC}/calc_stats.c
					${SRC}/user_account.c
					${SRC}/stats.c
					${SRC}/fifo_stats.c
					${SRC}/tick_generator.c
					${SRC}/tid_table.c
					${SRC}/log-decoder.c
					${SRC}/getsysinfo.c
					${SRC}/commands.c
					${SRC}/dbuser_map.c
					${SRC}/mysql_connector_common.c
					${config_SRC}
)
SET(governor_lib_src ${SRC}/dbgovernor_string_functions.c
					${SRC}/governor_write_data.c
					${SRC}/parce_proc_fs.c
					${SRC}/shared_memory.c
					${SRC}/log.c
)
SET_SOURCE_FILES_PROPERTIES(${db_governor_SRC} ${dbtop_SRC} ${governor_lib_src} ${mysql_unfreeze_SRC} ${dbctl_SRC} PROPERTIES COMPILE_FLAGS "-DOK -ggdb -fstack-protector-all")

ADD_EXECUTABLE(db_governor ${db_governor_SRC})
TARGET_LINK_LIBRARIES(db_governor ${LIBS})
ADD_EXECUTABLE(dbtop ${dbtop_SRC})
TARGET_LINK_LIBRARIES(dbtop ${LIBS})
ADD_EXECUTABLE(mysql_unfreeze ${mysql_unfreeze_SRC})
TARGET_LINK_LIBRARIES(mysql_unfreeze ${LIBS})
ADD_EXECUTABLE(dbctl ${dbctl_SRC})
TARGET_LINK_LIBRARIES(dbctl ${LIBS})

ADD_LIBRARY(governor SHARED ${governor_lib_src})
TARGET_COMPILE_DEFINITIONS(governor PRIVATE LIBGOVERNOR=1)
TARGET_LINK_LIBRARIES(governor pthread rt dl -Wl,-init,init_libgovernor -Wl,-fini,fini_libgovernor)
# TODO: Add cl-sentry and sentry to the list of libraries when sentry-native package will be available for all platforms

INSTALL(TARGETS db_governor dbtop mysql_unfreeze dbctl
  DESTINATION bin
  COMPONENT Runtime)

INSTALL(TARGETS governor
        DESTINATION lib
        PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)

######################################################
set(VERSION "1.0")
set(GOVERNOR_PATH governor-mysql-${VERSION})
set(tar_command "tar")
set(tar_args cfz 
             ../${GOVERNOR_PATH}/governor-mysql-${VERSION}.tar.bz2
             ../${GOVERNOR_PATH}/cmake/
             ../${GOVERNOR_PATH}/cron/
             ../${GOVERNOR_PATH}/install/
             ../${GOVERNOR_PATH}/mysql/
             ../${GOVERNOR_PATH}/script/
             ../${GOVERNOR_PATH}/src/
             ../${GOVERNOR_PATH}/tests/
             ../${GOVERNOR_PATH}/CMakeLists.txt
             ../${GOVERNOR_PATH}/db-governor.xml
             ../${GOVERNOR_PATH}/db-governor.xml.example
             ../${GOVERNOR_PATH}/db-governor.xml.test
             ../${GOVERNOR_PATH}/db_governor.spec
             ../${GOVERNOR_PATH}/LICENSE.TXT
   )

set(copy_arch "cp")
set(copy_target ./governor-mysql-${VERSION}.tar.bz2
                ~/rpmbuild/SOURCES/governor-mysql-${VERSION}.tar.bz2
   )

set(cpack_cmd "cpack")
set(cpack_args "")

set(link_cmd "ln")
set(rm_cmd "rm")
set(link_dir_src ${CMAKE_SOURCE_DIR})
set(link_dir_ver ../${GOVERNOR_PATH})
set(link_arg -s
             ${link_dir_src}
             ${link_dir_ver}
)

set(rm_arg -f
           ${link_dir_ver}
)

add_custom_target (
    sources
    COMMAND ${link_cmd} ${link_arg}
    COMMAND ${tar_command} ${tar_args}
    COMMAND ${rm_cmd} ${rm_arg}
)

add_custom_target (
    crtrpm
    COMMAND ${link_cmd} ${link_arg}
    COMMAND ${tar_command} ${tar_args}
    COMMAND ${copy_arch} ${copy_target}
    COMMAND ${cpack_cmd} ${cpack_args}
    COMMAND ${rm_cmd} ${rm_arg}
)

################################################################################3
set(VERSION "1.0.0")
set(CPACK_PACKAGE_VERSION_MAJOR 1)
set(CPACK_PACKAGE_VERSION_MINOR 0)
set(CPACK_PACKAGE_VERSION_PATCH 0)

set(CPACK_GENERATOR "RPM")
set(CPACK_PACKAGE_NAME "governor-mysql")
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_CONTACT "Shkatula PP")
set(CPACK_PACKAGE_VENDOR "CloudLinux Inc")
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")

set(CPACK_SOURCE_GENERATOR "TBZ2")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "governor-mysql-${VERSION}-Source")
set(CPACK_SOURCE_TBZ2 "ON")
set(CPACK_SOURCE_TGZ "OFF")
set(CPACK_SOURCE_TZ "OFF")
set(CPACK_SOURCE_ZIP "ON")

set(CPACK_RPM_USER_BINARY_SPECFILE "${CMAKE_CURRENT_BINARY_DIR}/db_governor.spec")
include(CPack)
