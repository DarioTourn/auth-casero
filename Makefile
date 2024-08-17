CC = gcc
CFLAGS = -fPIC -Wall -Wextra -Iinclude
LDFLAGS = -shared
TARGET = pam_my_module.so
SRC_DIR = src
INC_DIR = include
SRC_FILES = $(SRC_DIR)/auth-casero.c
OBJ_FILES = $(SRC_FILES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ_FILES)
	$(CC) $(LDFLAGS) -o $@ $^

$(OBJ_FILES): $(SRC_FILES) $(INC_DIR)/auth-casero.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ_FILES) $(TARGET)
