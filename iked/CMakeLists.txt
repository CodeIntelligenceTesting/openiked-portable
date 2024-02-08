# Copyright (c) 2020-2021 Tobias Heider <tobhe@openbsd.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckIncludeFiles)
include(GNUInstallDirs)

set(VERSIONED_FILES)
list(APPEND VERSIONED_FILES iked.c)

set(SRCS)
set(LIBS)

set(CFLAGS)
list(APPEND CFLAGS
	-O2
	-fstack-protector-strong
	-fPIE
	-D_FORTIFY_SOURCE=2
	-Wall
	-Wno-pointer-sign
	-Wno-deprecated-declarations
	-Wstrict-prototypes
	-Wmissing-prototypes
	-Wmissing-declarations
	-Wshadow
	-Wpointer-arith
	-Wcast-qual
	-Wsign-compare
	"$<$<CONFIG:DEBUG>:-O0;-g>"
)

add_library(iked-shared STATIC
	ca.c
	control.c
	config.c
	crypto.c
	dh.c
	eap.c
	ikev2.c
	ikev2_msg.c
	ikev2_pld.c
	imsg_util.c
	log.c
	policy.c
	print.c
	proc.c
	timer.c
	util.c
	# Generated files
	${CMAKE_CURRENT_BINARY_DIR}/ikev2_map.c
	${CMAKE_CURRENT_BINARY_DIR}/eap_map.c
	${CMAKE_CURRENT_BINARY_DIR}/parse.c
)

if(CMAKE_SYSTEM_NAME MATCHES "OpenBSD")
	target_sources(iked-shared PRIVATE ipsec.c pfkey.c)
elseif(CMAKE_SYSTEM_NAME MATCHES "Linux")
	target_sources(iked-shared PRIVATE ipsec.c pfkey.c)
elseif(CMAKE_SYSTEM_NAME MATCHES "Darwin")
	target_sources(iked-shared PRIVATE ipsec.c pfkey.c)
elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
	target_sources(iked-shared PRIVATE ipsec.c pfkey.c)
elseif(CMAKE_SYSTEM_NAME MATCHES "NetBSD")
	target_sources(iked-shared PRIVATE ipsec.c pfkey.c)
endif()
if(HAVE_VROUTE)
	list(APPEND SRCS vroute.c)
endif()
if(HAVE_VROUTE_NETLINK)
	list(APPEND SRCS vroute-netlink.c)
endif()
if (WITH_APPARMOR)
	list(APPEND SRCS apparmor.c)
endif()

list(APPEND SRCS
	chap_ms.c
	iked.c
	ikev2.h
	ocsp.c
	smult_curve25519_ref.c
	crypto_hash.c
	sntrup761.c
)

add_executable(iked ${SRCS})

target_compile_options(iked PRIVATE ${CFLAGS})
target_compile_options(iked-shared PRIVATE ${CFLAGS})
if(HAVE_LD_Z)
	target_link_options(iked PRIVATE "LINKER:-z,relro,-z,now")
endif()

target_include_directories(iked-shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(iked-shared PUBLIC libevent::core OpenSSL::SSL OpenSSL::Crypto compat)

if(DEFINED ENV{CLUSTERFUZZLITE})
	target_link_libraries(iked-shared PUBLIC "-lm")
else()
	target_link_libraries(iked-shared PRIVATE util)
endif()

list(APPEND LIBS iked-shared)

if (WITH_SYSTEMD)
	list(APPEND LIBS systemd)
endif()

target_link_libraries(iked
	PRIVATE ${LIBS}
)

add_custom_command(
	OUTPUT parse.c
	COMMAND yacc -o parse.c ${CMAKE_CURRENT_SOURCE_DIR}/parse.y
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/parse.y
)

add_custom_command(
	OUTPUT ikev2_map.c
	COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/genmap.sh
	    ${CMAKE_CURRENT_SOURCE_DIR}/ikev2.h ikev2 > ikev2_map.c
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/ikev2.h
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/genmap.sh
)

add_custom_command(
	OUTPUT eap_map.c
	COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/genmap.sh
	    ${CMAKE_CURRENT_SOURCE_DIR}/eap.h eap > eap_map.c
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/eap.h
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/genmap.sh
)

install(TARGETS iked RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(FILES ${CMAKE_SOURCE_DIR}/iked.conf
	PERMISSIONS OWNER_READ OWNER_WRITE 
	DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}
)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/iked.conf.5 DESTINATION ${CMAKE_INSTALL_MANDIR}/man5/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/iked.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8/)
if(WITH_APPARMOR)
	install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../linux/iked.apparmor
		DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/apparmor.d/
		RENAME usr.sbin.iked)
endif()
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/iked/ca)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/iked/certs)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/iked/crls)
install(DIRECTORY
	DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
	DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/iked/private
)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/iked/pubkeys/ipv4)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/iked/pubkeys/ipv6)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/iked/pubkeys/fqdn)
install(DIRECTORY DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/iked/pubkeys/ufqdn)
