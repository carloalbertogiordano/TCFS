# crypt-utils/CMakeLists.txt

# Define the library
add_library(crypt-utils
        crypt-utils.c
)

# Add current dir to included dirs
target_include_directories(crypt-utils PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Link library OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(crypt-utils OpenSSL::Crypto)

set_target_properties(crypt-utils PROPERTIES LINKER_LANGUAGE C)

# target_compile_options(crypt-utils PRIVATE -Wall -Wextra)
