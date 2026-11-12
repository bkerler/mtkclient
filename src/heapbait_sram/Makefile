TARGET  := heapbait_sram
DSTPATH := ../../mtkclient/payloads
ARCHS   := arm64 arm

CC_arm64 := aarch64-linux-gnu-gcc
LD_arm64 := aarch64-linux-gnu-gcc
OBJCOPY_arm64 := aarch64-linux-gnu-objcopy

CC_arm := arm-none-eabi-gcc
LD_arm := arm-none-eabi-gcc
OBJCOPY_arm := arm-none-eabi-objcopy

SRCS := $(wildcard *.c)

CFLAGS_arm64 := -std=gnu99 -Os -fno-stack-protector -fno-builtin-printf -fno-strict-aliasing -fno-builtin-memcpy -fPIE -Wall -Wextra -DNDEBUG
CFLAGS_arm   := -std=gnu99 -Os -mthumb -mcpu=cortex-a9 -fno-builtin-printf -fno-strict-aliasing -fno-builtin-memcpy -fPIE -mno-unaligned-access -Wall -Wextra

LDFLAGS := -nodefaultlibs -nostdlib -Wl,--build-id=none

.PHONY: all clean

all: $(patsubst %,$(DSTPATH)/$(TARGET)_%.bin,$(ARCHS))

define ARCH_TEMPLATE

OBJS_$(1) := $$(patsubst %.c,build/$(1)/%.o,$$(SRCS))

$(DSTPATH)/$(TARGET)_$(1).bin: build/$(1)/$(TARGET).elf
	mkdir -p $$(@D)
	$$(OBJCOPY_$(1)) -O binary $$^ $$@

build/$(1)/$(TARGET).elf: $$(OBJS_$(1)) shellcode_$(1).ld
	mkdir -p $$(@D)
	$$(LD_$(1)) -o $$@ $$(OBJS_$(1)) $$(LDFLAGS) -T shellcode_$(1).ld

build/$(1)/%.o: %.c
	mkdir -p $$(@D)
	$$(CC_$(1)) -c -o $$@ $$< $$(CFLAGS_$(1))

endef

$(foreach arch,$(ARCHS),$(eval $(call ARCH_TEMPLATE,$(arch))))

clean:
	rm -rf build
	rm -f $(foreach arch,$(ARCHS),$(DSTPATH)/$(TARGET)_$(arch).bin)
