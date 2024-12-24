# Указываем минимальную версию CMake
cmake_minimum_required(VERSION 3.5)

# Указываем имя проекта
project(XSSChecker)

# Указываем стандарт C++
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)


find_package(CURL REQUIRED)

# Указываем исходные файлы
set(SOURCES main.cpp)

# Создаем исполняемый файл
add_executable(XSSChecker ${SOURCES})

# Линкуем библиотеку libcurl с исполняемым файлом
target_link_libraries(XSSChecker PRIVATE CURL::libcurl)