cmake_minimum_required(VERSION 3.10)
project(my_ftp_server
    VERSION 1.0.0
    DESCRIPTION "Secure FTP Server with SSL/TLS support"
    LANGUAGES C
)

# C Standard
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
#set(CMAKE_C_EXTENSIONS OFF)

# Compiler flags
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

# Warning flags
add_compile_options(-Wall -Wextra -Wpedantic -Werror)

# Dependencies
find_package(OpenSSL REQUIRED)

# Source files
set(SOURCES
    server.c
    parser.c
    logger.c
    commands.c
)

# Main executable
add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    crypt
)

# Testing
option(BUILD_TESTING "Build unit tests" ON)

if(BUILD_TESTING)
    enable_testing()

    add_executable(parser_tests
        tests/test_parser.c
        parser.c
        logger.c
        commands.c
    )

    target_link_libraries(parser_tests PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        crypt
    )

    add_test(NAME ParserTest COMMAND parser_tests)
endif()
