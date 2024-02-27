# Define the linker options
LDFLAGS := -lssl -lcrypto -mavx2 -march=native -fopenmp

# Get the value of CRYPT_UTILS_OBJDIR
OBJDIR := $(CRYPT_UTILS_OBJDIR)

# Verify that OBJDIR is not empty
ifeq ($(OBJDIR),)
$(error CRYPT_UTILS_OBJDIR is not set)
endif

# Find all .c files in the current directory and subdirectories
SRCS := $(shell find . -name "*.c")

# Create the list of object files
OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS))

# Compiler
CC := gcc

# Compiler flags
CFLAGS := -Wall -Wextra -O2

# Rule to compile the object files
$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# Rule to create the library
$(OBJDIR)/crypt_utils_lib.a: $(OBJS)
	ar rcs $@ $^

# Rule to clean the object files and the library
clean:
	rm -f $(OBJS) $(OBJDIR)/crypt_utils_lib.a
