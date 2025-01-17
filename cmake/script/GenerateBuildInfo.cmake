# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

macro(fatal_error)
  message(FATAL_ERROR "\n"
    "Usage:\n"
    "  cmake -D BUILD_INFO_HEADER_PATH=<path> [-D SOURCE_DIR=<path>] -P ${CMAKE_CURRENT_LIST_FILE}\n"
    "All specified paths must be absolute ones.\n"
  )
endmacro()

if(DEFINED BUILD_INFO_HEADER_PATH AND IS_ABSOLUTE "${BUILD_INFO_HEADER_PATH}")
  if(EXISTS "${BUILD_INFO_HEADER_PATH}")
    file(STRINGS ${BUILD_INFO_HEADER_PATH} INFO LIMIT_COUNT 1)
  endif()
else()
  fatal_error()
endif()

if(DEFINED SOURCE_DIR)
  if(IS_ABSOLUTE "${SOURCE_DIR}" AND IS_DIRECTORY "${SOURCE_DIR}")
    set(WORKING_DIR ${SOURCE_DIR})
  else()
    fatal_error()
  endif()
else()
  set(WORKING_DIR ${CMAKE_CURRENT_SOURCE_DIR})
endif()

include(${WORKING_DIR}/cmake/script/GetGitInfo.cmake)
get_git_info(${WORKING_DIR})

if(GIT_TAG)
  set(NEWINFO "#define BUILD_GIT_TAG \"${GIT_TAG}\"")
elseif(GIT_COMMIT)
  set(NEWINFO "#define BUILD_GIT_COMMIT \"${GIT_COMMIT}\"")
else()
  set(NEWINFO "// No build information available")
endif()

# Only update the header if necessary.
if(NOT "${INFO}" STREQUAL "${NEWINFO}")
  file(WRITE ${BUILD_INFO_HEADER_PATH} "${NEWINFO}\n")
endif()
