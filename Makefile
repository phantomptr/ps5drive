VERSION := $(shell cat VERSION)

PAYLOAD_TARGET := payload/ps5drive.elf
KILLER_TARGET := payload/ps5drivekiller.elf
PAYLOAD_SRCS := payload/main.c payload/server.c payload/notify.c
PAYLOAD_OBJS := $(PAYLOAD_SRCS:.c=.o)
KILLER_SRCS := payload/killer.c payload/notify.c
KILLER_OBJS := $(KILLER_SRCS:.c=.o)
COMMON_HDRS := payload/config.h payload/server.h payload/notify.h

HOST_CC ?= cc
HOST_TARGET := build/ps5drive_host
HOST_SRCS := payload/main.c payload/server.c payload/notify_host.c
HOST_OBJS := $(patsubst payload/%.c,build/host/%.o,$(HOST_SRCS))
HOST_CFLAGS := -Wall -Wextra -O2 -g -DPS5DRIVE_HOST_BUILD=1 -DPS5DRIVE_VERSION=\"$(VERSION)\"
HOST_LDADD := -lpthread

SDK_REQUIRED_GOALS := all payload killer info test-remote
NEED_SDK := $(filter $(SDK_REQUIRED_GOALS),$(if $(MAKECMDGOALS),$(MAKECMDGOALS),all))

ifneq ($(NEED_SDK),)
ifndef PS5_PAYLOAD_SDK
$(error PS5_PAYLOAD_SDK is not set. Please export PS5_PAYLOAD_SDK=/path/to/sdk)
endif
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
PAYLOAD_CFLAGS := -Wall -O2 -flto -DPS5DRIVE_VERSION=\"$(VERSION)\"
PAYLOAD_LDADD := -lkernel -lpthread
endif

.PHONY: all payload killer host test test-remote clean info

all: payload killer
	@echo "Built $(PAYLOAD_TARGET) (version $(VERSION))"
	@echo "Built $(KILLER_TARGET) (version $(VERSION))"

payload: $(PAYLOAD_TARGET)

killer: $(KILLER_TARGET)

$(PAYLOAD_TARGET): $(PAYLOAD_OBJS) VERSION
	$(CC) $(PAYLOAD_CFLAGS) -o $@ $(PAYLOAD_OBJS) $(PAYLOAD_LDADD)

$(KILLER_TARGET): $(KILLER_OBJS) VERSION
	$(CC) $(PAYLOAD_CFLAGS) -o $@ $(KILLER_OBJS) $(PAYLOAD_LDADD)

payload/%.o: payload/%.c $(COMMON_HDRS) VERSION
	$(CC) $(PAYLOAD_CFLAGS) -c $< -o $@

host: $(HOST_TARGET)

$(HOST_TARGET): $(HOST_OBJS) VERSION | build
	$(HOST_CC) $(HOST_CFLAGS) -o $@ $(HOST_OBJS) $(HOST_LDADD)

build:
	mkdir -p build

build/host/%.o: payload/%.c $(COMMON_HDRS) VERSION
	mkdir -p $(dir $@)
	$(HOST_CC) $(HOST_CFLAGS) -c $< -o $@

test: host
	python3 -m unittest -v tests/test_integration.py

test-remote: payload killer
	python3 -m unittest -v tests/test_ps5_remote.py

clean:
	rm -f $(PAYLOAD_TARGET) $(KILLER_TARGET) $(PAYLOAD_OBJS) $(KILLER_OBJS)
	rm -rf build

info:
	@echo "VERSION=$(VERSION)"
	@echo "PAYLOAD_TARGET=$(PAYLOAD_TARGET)"
	@echo "KILLER_TARGET=$(KILLER_TARGET)"
	@echo "HOST_TARGET=$(HOST_TARGET)"
