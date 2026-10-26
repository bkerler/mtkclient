CC := aarch64-linux-gnu-gcc
LD := aarch64-linux-gnu-gcc
OBJCOPY := aarch64-linux-gnu-objcopy

TARGET := heapbait_sram

DSTPATH := ../../mtkclient/payloads

SRCS := $(wildcard *.c)
OBJS := $(patsubst %.c,%.o,$(wildcard *.c))

CFLAGS := -std=gnu99 -Os -fno-stack-protector -fno-builtin-printf -fno-strict-aliasing -fno-builtin-memcpy -fPIE -Wall -Wextra -DNDEBUG
LDFLAGS := -nodefaultlibs -nostdlib -Wl,--build-id=none

all: $(DSTPATH)/$(TARGET).bin

$(DSTPATH)/$(TARGET).bin: $(TARGET).elf
	$(OBJCOPY) -O binary $^ $@

$(TARGET).elf: $(OBJS) shellcode.ld
	$(LD) -o $@ $(OBJS) $(LDFLAGS) -T shellcode.ld

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f $(OBJS) $(TARGET).elf $(DSTPATH)/$(TARGET).bin
