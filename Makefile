CC      = gcc
CFLAGS  = -Wall -Wextra -g -Iinclude
SRCS    = src/utils.c src/router_init.c src/route.c \
          src/arp.c src/acl.c src/forward.c src/main.c
TARGET  = router_sim

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

.PHONY: all clean
