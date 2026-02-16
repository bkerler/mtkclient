#include <stdint.h>

volatile uint32_t *wdt = (volatile uint32_t *)0x10007000;
uint32_t (*usbdl_put_word)() = 0;
uint32_t (*usbdl_put_data)() = 0;

uint32_t searchptr(uint32_t startoffset, uint32_t endoffset) {
    for (uint32_t offset = startoffset; offset < endoffset; offset += 4) {
            if ((((uint32_t *)offset)[0] == 0x5500AA0) && (((((uint32_t *)offset)[1])&0xFFFFFF00) == 0x0))
                return offset;
    }
    return 0;
}

uint32_t * ldr_lit(const uint32_t curpc, uint16_t instr, uint8_t *Rt) {
    //#LDR (literal), LDR R1, =SEC_REG
    uint8_t imm8 = instr & 0xFF;
    if (Rt) *Rt = (instr >> 8) & 7;
    uint32_t pc = (((uint32_t)curpc) / 4 * 4);
    return (uint32_t *)(pc + (imm8 * 4) + 4);
}

__attribute__ ((section(".text.main"))) int main() {
    volatile uint32_t brom_base=0;
    if (((uint32_t *)(brom_base))[0]==0xe51ff004)
        brom_base=((uint32_t *)(brom_base))[1];

    uint32_t offset = searchptr(brom_base + 0x1000, brom_base + 0x20000);
    if (offset){
        usbdl_put_word=(void*)(*((uint32_t*)((offset-0x1C)))|1);
        usbdl_put_data=(void*)(*((uint32_t*)((offset-0xC)))|1);
        int (*(*usbdl_ptr))() = (void *)(ldr_lit((uint32_t)usbdl_put_word + 7, ((uint16_t*)(usbdl_put_word + 7))[0], 0));
        //Fix ptr_send
        *(volatile uint32_t *)(usbdl_ptr[0] + 8) = (uint32_t)usbdl_ptr[2];

        int ack = __builtin_bswap32(0xC1C2C3C4);
        usbdl_put_data(&ack, 4);
        int length = __builtin_bswap32(0x20000);
        usbdl_put_data(&length, 4);
        length = __builtin_bswap32(length);
        usbdl_put_data((void *)brom_base, length);
    }

    // Reboot device, so we still get feedback in case the above didn't work
    wdt[8/4] = 0x1971;
    wdt[0/4] = 0x22000014;
    wdt[0x14/4] = 0x1209;

    while (1) {

    }
}