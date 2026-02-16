ifneq (,$(findstring arm-linux-gnueabihf,$(shell gcc -dumpmachine)))
CC := gcc
AS := as
LD := gcc
OBJCOPY := objcopy
else
CC := arm-none-eabi-gcc
AS := arm-none-eabi-as
LD := arm-none-eabi-gcc
OBJCOPY := arm-none-eabi-objcopy
endif

VPATH := targets common generic
DSTPATH := ../../payloads

SOCS := mt2601 mt6261 mt6572 mt6575 mt6580 mt6582 mt6592 mt6595 mt6735 mt6737 mt6739 mt6752 mt6753 mt6755 mt6757 mt6758 mt6761 mt6763 mt6765 mt6768 mt6771 mt6779 mt6781 mt6785 mt6795 mt6797 mt6799 mt6833 mt6853 mt6873 mt6877 mt6885 mt6893 mt8127 mt8163 mt8167 mt8168 mt8173 mt8176 mt8512 mt8590 mt8695 generic_dump generic_reboot generic_uart_dump generic_patcher generic_loader generic_preloader_dump generic_stage1 generic_sram
PAYLOADS := $(SOCS:%=$(DSTPATH)/%_payload.bin)

CFLAGS := -std=gnu99 -Os -mthumb -mcpu=cortex-a9 -fno-builtin-printf -fno-strict-aliasing -fno-builtin-memcpy -fPIE -mno-unaligned-access -Wall -Wextra
LDFLAGS := -nodefaultlibs -nostdlib -Wl,--build-id=none

all: CFLAGS += -DNDEBUG
all: makepayloads

debug: CFLAGS += -DDEBUG -g
debug: makepayloads

makepayloads: $(PAYLOADS)

$(DSTPATH)/%_payload.bin: $(DSTPATH)/%.elf
	$(OBJCOPY) -O binary $^ $@

$(DSTPATH)/%.elf: $(DSTPATH)/%.o $(DSTPATH)/start.o common/generic.ld
	$(LD) -o $@ $(DSTPATH)/$*.o $(DSTPATH)/start.o $(LDFLAGS) -T common/generic.ld

$(DSTPATH)/%_loader.elf: $(DSTPATH)/%_loader.o common/loader.ld
	$(LD) -o $@ $(DSTPATH)/$*_loader.o $(LDFLAGS) -T common/loader.ld

$(DSTPATH)/generic_%.o: generic_%.c
	mkdir -p $(@D)
	$(CC) -c -o $@ $< $(CFLAGS)

$(DSTPATH)/%_loader.o: %_loader.c
	mkdir -p $(@D)
	$(CC) -c -o $@ $< $(CFLAGS)

$(DSTPATH)/%.o: common.c %.h
	mkdir -p $(@D)
	$(CC) -c -o $@ common/common.c -D DEVICE_HEADER=../targets/$*.h $(CFLAGS)

$(DSTPATH)/%.o: %.S
	mkdir -p $(@D)
	$(AS) -o $@ $<

clean:
	-rm -rf $(DSTPATH)
