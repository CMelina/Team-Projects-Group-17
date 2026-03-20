cmake_minimum_required(VERSION 3.20)
project(red_circles LANGUAGES NONE)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_custom_target(run_red_circles
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/main.py ${INPUT_DIR} ${CROPS_DIR} ${CROP_SCALE}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running Python red circle detector"
)