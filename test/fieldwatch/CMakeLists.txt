add_executable(FieldwatchTest FieldwatchTest.cpp ${REPO_ROOT}/lib/Fieldwatch/Fieldwatch.cpp)

target_include_directories(FieldwatchTest PRIVATE ${REPO_ROOT}/lib/Fieldwatch)

target_link_libraries(FieldwatchTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(FieldwatchTest)
