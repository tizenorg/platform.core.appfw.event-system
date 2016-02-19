CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

PROJECT(esd C)

SET(VERSION 0.0.1)
SET(VERSION_MAJOR 0)

SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")

set(CMAKE_SKIP_BUILD_RPATH true)

### Local include directories
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)

### Required packages
INCLUDE(FindPkgConfig)

pkg_check_modules(pkgs REQUIRED dlog bundle pkgmgr-info glib-2.0 gio-2.0 appsvc aul ecore vconf libtzplatform-config libsystemd-daemon cynara-client cynara-creds-gdbus cynara-session security-manager)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

#FIND_LIBRARY(LIB_DL dl)

## Additional flag
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -g -Wall")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

## Linker flags
SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")

##build eventsystem daemon
add_executable(esd
	src/esd_main.c
	src/esd_system_event.c
)
TARGET_LINK_LIBRARIES(esd eventsystem pkgmgr-client ${pkgs_LDFLAGS})
SET_TARGET_PROPERTIES(esd PROPERTIES COMPILE_FLAGS ${CFLAGS} "-fPIE")
SET_TARGET_PROPERTIES(esd PROPERTIES LINK_FLAGS "-pie")

# pkgconfig file
configure_file(esd.manifest.in esd.manifest @ONLY)

INSTALL(TARGETS esd DESTINATION bin)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/eventsystem.conf DESTINATION /etc/dbus-1/system.d)
