CC = gcc
LD = gcc
MKDIR = mkdir
RMDIR = rmdir
RM = rm -rf
CFLAGS = -g -O0 -Wall
LD_FLAGS =

SRC = src
DST = bin

TARGET = js-parser
OBJS = byte-code.o common.o js-lexer.o \
       js-parser.o js-parser-mem.o js-parser-postproc.o \
       js-parser-util.o main.o

TARGET_FILE = $(DST)/$(TARGET)
OBJ_FILES = $(addprefix $(DST)/, $(OBJS))

.PHONY: all
all: $(TARGET_FILE)

$(DST) :
	$(MKDIR) $(DST)

$(DST)/%.o : $(SRC)/%.c
	$(CC) $(CFLAGS) $^ -c -o $@

$(TARGET_FILE) : $(DST) $(OBJ_FILES)
	$(LD) $(CFLAGS) $(LD_FLAGS) $(OBJ_FILES) -o $@

clean:
	$(RM) $(DST)
