ifndef PS5_PAYLOAD_SDK
$(error PS5_PAYLOAD_SDK is not set. Please export PS5_PAYLOAD_SDK=/path/to/sdk)
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

TARGET := payload/ps5drive.elf
KILLER_TARGET := payload/ps5drivekiller.elf
VERSION := $(shell cat VERSION)

SRCS := payload/main.c payload/notify.c
OBJS := $(SRCS:.c=.o)
KILLER_SRCS := payload/killer.c payload/notify.c
KILLER_OBJS := $(KILLER_SRCS:.c=.o)

CFLAGS := -Wall -O2 -flto -DPS5DRIVE_VERSION=\"$(VERSION)\"
LDADD := -lkernel -lpthread

.PHONY: all clean info killer

all: $(TARGET) $(KILLER_TARGET)
	@echo "Built $(TARGET) (version $(VERSION))"
	@echo "Built $(KILLER_TARGET) (version $(VERSION))"

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDADD)

$(KILLER_TARGET): $(KILLER_OBJS)
	$(CC) $(CFLAGS) -o $@ $(KILLER_OBJS) $(LDADD)

killer: $(KILLER_TARGET)
	@echo "Built $(KILLER_TARGET) (version $(VERSION))"

payload/%.o: payload/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(KILLER_TARGET) $(OBJS) $(KILLER_OBJS)

info:
	@echo "PS5_PAYLOAD_SDK=$(PS5_PAYLOAD_SDK)"
	@echo "TARGET=$(TARGET)"
	@echo "VERSION=$(VERSION)"
