# Copyright (c) 2025-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

function(get_git_info WORKING_DIR)
  set(GIT_TAG "")
  set(GIT_COMMIT "")
  if(NOT "$ENV{BITCOIN_GENBUILD_NO_GIT}" STREQUAL "1")
    find_package(Git QUIET)
    if(Git_FOUND)
      execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --is-inside-work-tree
        WORKING_DIRECTORY ${WORKING_DIR}
        OUTPUT_VARIABLE IS_INSIDE_WORK_TREE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
      )
      if(IS_INSIDE_WORK_TREE)
        # ... existing git commands ...
        if(HEAD_COMMIT STREQUAL MOST_RECENT_TAG_COMMIT AND NOT IS_DIRTY)
          set(GIT_TAG ${MOST_RECENT_TAG} CACHE INTERNAL "Git tag")
        else()
          execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-parse --short=12 HEAD
            WORKING_DIRECTORY ${WORKING_DIR}
            OUTPUT_VARIABLE GIT_COMMIT
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
          )
          if(IS_DIRTY)
            string(APPEND GIT_COMMIT "-dirty")
          endif()
          set(GIT_COMMIT ${GIT_COMMIT} CACHE INTERNAL "Git commit")
        endif()
      endif()
    endif()
  endif()
endfunction()
