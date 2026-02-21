VERSION := $(shell cat VERSION)

PAYLOAD_SRCS := payload/main.c payload/server.c payload/notify.c
PS4_EXTRA_SRCS := payload/ps4_compat.c payload/ps4_entry.c
COMMON_HDRS := payload/config.h payload/server.h payload/notify.h payload/ps4_compat.h

PS5_PAYLOAD_TARGET := payload/ps5drive.elf
PS4_PAYLOAD_TARGET := payload/ps4drive.elf

PS5_PAYLOAD_OBJS := $(patsubst payload/%.c,build/ps5/%.o,$(PAYLOAD_SRCS))
PS4_PAYLOAD_SRCS := $(PAYLOAD_SRCS) $(PS4_EXTRA_SRCS)
PS4_PAYLOAD_OBJS := $(patsubst payload/%.c,build/ps4/%.o,$(PS4_PAYLOAD_SRCS))

HOST_CC ?= cc
HOST_TARGET := build/ps5drive_host
HOST_SRCS := payload/main.c payload/server.c payload/notify_host.c
HOST_OBJS := $(patsubst payload/%.c,build/host/%.o,$(HOST_SRCS))
HOST_CFLAGS := -Wall -Wextra -O2 -g -DPS5DRIVE_HOST_BUILD=1 -DPS5DRIVE_VERSION=\"$(VERSION)\"
HOST_LDADD := -lpthread

GOALS := $(if $(MAKECMDGOALS),$(MAKECMDGOALS),all)
PS5_REQUIRED_GOALS := all ps5 both payload payload-ps5 test-integration-real test-remote info
PS4_REQUIRED_GOALS := ps4 both payload-ps4 info
NEED_PS5 := $(filter $(PS5_REQUIRED_GOALS),$(GOALS))
NEED_PS4 := $(filter $(PS4_REQUIRED_GOALS),$(GOALS))

ifneq ($(NEED_PS5),)
ifndef PS5_PAYLOAD_SDK
$(error PS5_PAYLOAD_SDK is not set. Please export PS5_PAYLOAD_SDK=/path/to/sdk)
endif
PS5_TOOLCHAIN_MK ?= $(firstword $(wildcard $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk $(PS5_PAYLOAD_SDK)/prospero.mk))
ifeq ($(strip $(PS5_TOOLCHAIN_MK)),)
$(error Could not find PS5 toolchain makefile. Set PS5_PAYLOAD_SDK or PS5_TOOLCHAIN_MK=/path/to/prospero.mk)
endif
include $(PS5_TOOLCHAIN_MK)
PS5_CC := $(CC)
PS5_PAYLOAD_CFLAGS := -Wall -O2 -flto -DPS5DRIVE_VERSION=\"$(VERSION)\"
PS5_PAYLOAD_LDADD := -lkernel -lpthread
endif

ifneq ($(NEED_PS4),)
ifndef PS4_PAYLOAD_SDK
$(error PS4_PAYLOAD_SDK is not set. Please export PS4_PAYLOAD_SDK=/path/to/sdk)
endif
PS4_TOOLCHAIN_MK ?= $(firstword $(wildcard \
	$(PS4_PAYLOAD_SDK)/toolchain/orbis.mk \
	$(PS4_PAYLOAD_SDK)/toolchain/ps4.mk \
	$(PS4_PAYLOAD_SDK)/orbis.mk \
	$(PS4_PAYLOAD_SDK)/ps4.mk))
ifneq ($(strip $(PS4_TOOLCHAIN_MK)),)
include $(PS4_TOOLCHAIN_MK)
PS4_CC := $(CC)
PS4_COMPAT_HEADER := $(firstword $(wildcard \
	$(PS4_PAYLOAD_SDK)/ps4.h \
	$(PS4_PAYLOAD_SDK)/include/ps4.h \
	$(PS4_PAYLOAD_SDK)/libPS4/include/ps4.h))
ifneq ($(strip $(PS4_COMPAT_HEADER)),)
PS4_PAYLOAD_CFLAGS := \
	-I$(PS4_PAYLOAD_SDK) \
	-I$(PS4_PAYLOAD_SDK)/include \
	-I$(PS4_PAYLOAD_SDK)/libPS4/include \
	-Wall -O2 \
	-DPS5DRIVE_TARGET_PS4=1 \
	-DPS5DRIVE_PS4_BUILD=1 \
	-DPS5DRIVE_VERSION=\"$(VERSION)\"
PS4_COMPAT_MODE := enabled
else
PS4_PAYLOAD_CFLAGS := -Wall -O2 -DPS5DRIVE_TARGET_PS4=1 -DPS5DRIVE_VERSION=\"$(VERSION)\"
PS4_COMPAT_MODE := disabled
endif
PS4_PAYLOAD_LDADD := -lkernel
PS4_PAYLOAD_LDFLAGS :=
PS4_BUILD_MODE := toolchain-mk
else
PS4_LIBPS4_ROOT := $(if $(wildcard $(PS4_PAYLOAD_SDK)/libPS4/libPS4.a),$(PS4_PAYLOAD_SDK),)
ifeq ($(strip $(PS4_LIBPS4_ROOT)),)
$(error Could not find PS4 toolchain makefile or libPS4 SDK assets under PS4_PAYLOAD_SDK='$(PS4_PAYLOAD_SDK)')
endif
PS4_CC ?= gcc
PS4_PAYLOAD_CFLAGS := \
	-I$(PS4_LIBPS4_ROOT)/libPS4/include \
	-Wall -Wextra -Os -std=gnu11 \
	-ffunction-sections -fdata-sections \
	-fno-builtin -fno-stack-protector \
	-masm=intel -march=btver2 -mtune=btver2 -m64 -mabi=sysv -mcmodel=small \
	-fpie -fPIC \
	-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
	-DPS5DRIVE_TARGET_PS4=1 \
	-DPS5DRIVE_PS4_BUILD=1 \
	-DPS5DRIVE_VERSION=\"$(VERSION)\"
PS4_PAYLOAD_LDFLAGS := \
	-nostartfiles -nostdlib \
	-Wl,-T,$(PS4_LIBPS4_ROOT)/libPS4/linker.x \
	-Wl,--gc-sections
PS4_PAYLOAD_LDADD := \
	$(PS4_LIBPS4_ROOT)/libPS4/crt0.s \
	$(PS4_LIBPS4_ROOT)/libPS4/libPS4.a
PS4_BUILD_MODE := libPS4
PS4_COMPAT_MODE := enabled
endif
endif

.PHONY: all ps5 ps4 both payload payload-ps5 payload-ps4 host \
	test test-common test-unit \
	test-ps5-mock test-ps4-mock test-integration-mock \
	test-ps5-real test-integration-real test-remote \
	clean info

all: ps5

ps5: payload-ps5
	@echo "Built $(PS5_PAYLOAD_TARGET) (version $(VERSION))"

ps4: payload-ps4
	@echo "Built $(PS4_PAYLOAD_TARGET) (version $(VERSION))"

both: ps5 ps4

payload: payload-ps5

payload-ps5: $(PS5_PAYLOAD_TARGET)

payload-ps4: $(PS4_PAYLOAD_TARGET)

$(PS5_PAYLOAD_TARGET): $(PS5_PAYLOAD_OBJS) VERSION | build
	$(PS5_CC) $(PS5_PAYLOAD_CFLAGS) -o $@ $(PS5_PAYLOAD_OBJS) $(PS5_PAYLOAD_LDADD)

$(PS4_PAYLOAD_TARGET): $(PS4_PAYLOAD_OBJS) VERSION | build
	$(PS4_CC) $(PS4_PAYLOAD_LDFLAGS) $(PS4_PAYLOAD_CFLAGS) -o $@ $(PS4_PAYLOAD_OBJS) $(PS4_PAYLOAD_LDADD)

build/ps5/%.o: payload/%.c $(COMMON_HDRS) VERSION | build
	mkdir -p $(dir $@)
	$(PS5_CC) $(PS5_PAYLOAD_CFLAGS) -c $< -o $@

build/ps4/%.o: payload/%.c $(COMMON_HDRS) VERSION | build
	mkdir -p $(dir $@)
	$(PS4_CC) $(PS4_PAYLOAD_CFLAGS) -c $< -o $@

host: $(HOST_TARGET)

$(HOST_TARGET): $(HOST_OBJS) VERSION | build
	$(HOST_CC) $(HOST_CFLAGS) -o $@ $(HOST_OBJS) $(HOST_LDADD)

build:
	mkdir -p build

build/host/%.o: payload/%.c $(COMMON_HDRS) VERSION
	mkdir -p $(dir $@)
	$(HOST_CC) $(HOST_CFLAGS) -c $< -o $@

test: test-unit test-integration-mock

test-common:
	python3 -m unittest discover -v -s tests/common/unit -p 'test_*.py'

test-unit: test-common

test-ps5-mock: host
	python3 -m unittest discover -v -s tests/ps5/integration/mock -p 'test_*.py'

test-ps4-mock: host
	python3 -m unittest discover -v -s tests/ps4/integration/mock -p 'test_*.py'

test-integration-mock: test-ps5-mock test-ps4-mock

test-ps5-real: payload-ps5
	python3 -m unittest discover -v -s tests/ps5/integration/real -p 'test_*.py'

test-integration-real: test-ps5-real

test-remote: test-integration-real

clean:
	rm -f $(PS5_PAYLOAD_TARGET) $(PS4_PAYLOAD_TARGET)
	rm -rf build

info:
	@echo "VERSION=$(VERSION)"
	@echo "PS5_PAYLOAD_TARGET=$(PS5_PAYLOAD_TARGET)"
	@echo "PS4_PAYLOAD_TARGET=$(PS4_PAYLOAD_TARGET)"
	@echo "PS5_PAYLOAD_SDK=$(PS5_PAYLOAD_SDK)"
	@echo "PS4_PAYLOAD_SDK=$(PS4_PAYLOAD_SDK)"
	@echo "PS5_TOOLCHAIN_MK=$(PS5_TOOLCHAIN_MK)"
	@echo "PS4_TOOLCHAIN_MK=$(PS4_TOOLCHAIN_MK)"
	@echo "PS4_LIBPS4_ROOT=$(PS4_LIBPS4_ROOT)"
	@echo "PS4_COMPAT_HEADER=$(PS4_COMPAT_HEADER)"
	@echo "PS4_COMPAT_MODE=$(PS4_COMPAT_MODE)"
	@echo "PS4_BUILD_MODE=$(PS4_BUILD_MODE)"
	@echo "HOST_TARGET=$(HOST_TARGET)"
