cmake_minimum_required(VERSION 3.10)
project(lure C)

set(CMAKE_C_STANDARD 99)

SET(GCC_COVERAGE_LINK_FLAGS    "-lpcap" )

# with -fPIC
 IF(UNIX AND NOT WIN32)
   FIND_PROGRAM(CMAKE_UNAME uname /bin /usr/bin /usr/local/bin )
   IF(CMAKE_UNAME)
     EXEC_PROGRAM(uname ARGS -m OUTPUT_VARIABLE CMAKE_SYSTEM_PROCESSOR)
     SET(CMAKE_SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR} CACHE INTERNAL
 "processor type (i386 and x86_64)")
      IF(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
       ADD_DEFINITIONS(-fPIC)
     ENDIF(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
   ENDIF(CMAKE_UNAME)
 ENDIF(UNIX AND NOT WIN32)
include(FindPCAP.cmake)

add_executable(lure main.c parsePacket.c parsePacket.h ieee80211.h sendPacket.c sendPacket.h ieee80211_radiotap.h common/common.h common/common.c socketTest/server.c common/send_frame.c common/send_frame.h common/msg.h common/log.c common/log.h common/util.c common/util.h common/ConfigINI.h audit_comm.h audit_comm.c radiotap_parser.h radiotap_parser.c)

target_link_libraries(lure ${PCAP_LIBRARY})