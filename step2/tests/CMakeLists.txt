add_executable(edgetest edgetest.c)
target_link_libraries(edgetest PUBLIC zhpeq zhpeq_util)

add_executable(libzhpeq_ld libzhpeq_ld.c)
target_link_libraries(libzhpeq_ld PUBLIC zhpeq zhpeq_util)

add_executable(libzhpeq_mr libzhpeq_mr.c)
target_link_libraries(libzhpeq_mr PUBLIC zhpeq zhpeq_util)

add_executable(libzhpeq_qalloc libzhpeq_qalloc.c)
target_link_libraries(libzhpeq_qalloc PUBLIC zhpeq zhpeq_util)

add_executable(libzhpeq_qattr libzhpeq_qattr.c)
target_link_libraries(libzhpeq_qattr PUBLIC zhpeq zhpeq_util)

add_executable(libzhpeq_regtime libzhpeq_regtime.c)
target_link_libraries(libzhpeq_regtime PUBLIC zhpeq zhpeq_util)

add_executable(libzhpeq_util_log libzhpeq_util_log.c)
target_link_libraries(libzhpeq_util_log PUBLIC zhpeq_util)

add_executable(xingpong xingpong.c)
target_link_libraries(xingpong PUBLIC zhpeq zhpeq_util)

install(
  TARGETS
  edgetest
  libzhpeq_ld
  libzhpeq_mr
  libzhpeq_qalloc
  libzhpeq_qattr
  libzhpeq_regtime
  libzhpeq_util_log
  xingpong
  DESTINATION libexec)
