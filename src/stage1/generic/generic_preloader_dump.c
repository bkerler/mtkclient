#include <stdint.h>

volatile uint32_t *wdt = (volatile uint32_t *)0x10007000;

static const uint16_t searchpattern2[3]={0x4D4D, 0x014D, 0x38};
volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x0;
volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x0;
volatile uint32_t *uart_base = (volatile uint32_t *)0x11002000;

uint32_t (*usbdl_put_word)() = 0;
uint32_t (*usbdl_get_data)() = 0;
uint32_t (*usbdl_put_data)() = 0;
uint32_t (*cmd_handler)() = 0;

void low_uart_put(int ch) {
    while ( !((*uart_reg0) & 0x20) )
    {}
    *uart_reg1 = ch;
}

uint32_t recv_dword(){
    uint32_t value;
    usbdl_get_data(&value,4);
    return __builtin_bswap32(value);
}

void _putchar(char character)
{
    if (character == '\n')
        low_uart_put('\r');
    low_uart_put(character);
}

int print(char* s){
    char c = s[0];
    int i = 0;
    while(c){
        _putchar(c);
        c = s[++i];
    }
    return i;
}

uint32_t searchfunc(uint32_t startoffset, uint32_t endoffset, const uint16_t *pattern, uint8_t patternsize) {
    uint8_t matched = 0;
    for (uint32_t offset = startoffset; offset < endoffset; offset += 2) {
        for (uint32_t i = 0; i < patternsize; i++) {
            if (((uint16_t *)offset)[i] != pattern[i]) {
                matched = 0;
                break;
            }
            if (++matched == patternsize) return offset;
        }
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
    uint32_t offset = 0;
    uint32_t offs1 = 0;
    volatile uint32_t brom_base=0;
    if (((uint32_t *)(brom_base))[0]==0xe51ff004)
        brom_base=((uint32_t *)(brom_base))[1];

    /* A warm welcome to uart */
    static const uint16_t uartb[3] = {0x5F31, 0x4E45, 0x0F93};
    offs1 = searchfunc(brom_base + 0x100, brom_base + 0x14000, uartb, 3);
    if (offs1) {
        uart_base = (volatile uint32_t *)(((uint32_t *)(offs1 + 0x8))[0] & 0xFFFFFFFF);
        uart_reg0 = (volatile uint32_t*)((volatile uint32_t)uart_base + 0x14);
        uart_reg1 = (volatile uint32_t*)uart_base;
    }

    uint32_t bromstart= brom_base + 0x100;
    uint32_t bromend= brom_base + 0x20000;
    static const uint16_t sddc[2] = {0xF7FF, 0xFFF4};
    static const uint16_t sddd[1] = {0xB510};
    offs1 = (uint32_t)(searchfunc(bromstart, bromend, sddc, 2));
    if (offs1)
    {
        cmd_handler = (void*)(offs1|1);
    }
    else {
        offs1 = (uint32_t)(searchfunc(bromstart, bromend, sddd, 1));
        if ((((uint32_t *)(offs1 + 0x4))[0] & 0xFFFF00FF)==0x210000F4) {
            cmd_handler = (void*)(offs1|1);
        }
        else {
            cmd_handler = (void*)0;
        }
    }

    offset = searchfunc(0x200000, 0x200000 + 0x10000,searchpattern2,3);
    if (!offset){
        offset = searchfunc(0x2000000, 0x2000000 + 0x10000,searchpattern2,3);
    }
    /* usbdl_put_data here we are ... */
    static const uint16_t sdda[2] = {0x0AA0, 0x0550};
    offs1 = (uint32_t)(searchfunc(bromstart, bromend, sdda, 2));
    if (offs1)
    {
        offs1 = (uint32_t)(searchfunc(offs1+0x4, bromend, sdda, 2));
        if (offs1)
        {
            usbdl_put_word=(void*)(*((uint32_t*)((offs1-0x1C))));
            usbdl_get_data=(void*)(*((uint32_t*)((offs1-0x10)))|1);
            usbdl_put_data=(void*)(*((uint32_t*)((offs1-0xC)))|1);
            int (*(*usbdl_ptr))() = (void *)(ldr_lit((uint32_t)usbdl_put_word + 7, ((uint16_t*)(usbdl_put_word + 7))[0], 0));
            //Fix ptr_send
            *(volatile uint32_t *)(usbdl_ptr[0] + 8) = (uint32_t)usbdl_ptr[2];
            int ack = __builtin_bswap32(0xC1C2C3C4);
            usbdl_put_data(&ack, 4);
            int length = 0;
            if (offset){
                length = ((uint32_t*)offset)[8];
                usbdl_put_data(&length, 4);
                usbdl_put_data((void *)offset, length);
                }
            else {
                usbdl_put_data(&length, 4);
            }
        }
    }
    return cmd_handler();
}
