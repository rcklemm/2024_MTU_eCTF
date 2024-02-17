CC = gcc
CFLAGS = -Wall -Wextra -I.  # Compiler flags
LDFLAGS = -L. -L/usr/local/lib   # Linker flags
LDLIBS = -lwolfssl         # Libraries to link against

SRCS = test_crypto.c crypto_util.c                # Source files
OBJS = $(SRCS:.c=.o)         # Object files
TARGET = test                # Executable name

HEADER = crypto_util.h          # Header file

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c $(HEADER)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(OBJS) $(TARGET)
