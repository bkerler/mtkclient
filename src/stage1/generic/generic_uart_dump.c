// (c) 2021 by k4y0z
#include <stdint.h>

volatile uint32_t *wdt = (volatile uint32_t *)0x10007000;
volatile uint32_t *uart_base = (volatile uint32_t *)0x11002000;


void low_uart_put(int ch) {
    volatile uint32_t *uart_reg0 = (volatile uint32_t*)((volatile uint32_t)uart_base + 0x14);
    volatile uint32_t *uart_reg1 = (volatile uint32_t*)uart_base;

    while ( !((*uart_reg0) & 0x20) )
    {}

    *uart_reg1 = ch;
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

void hex_dump(const void* data, uint32_t size) {
    static const char hex[] = "0123456789ABCDEF";
    uint32_t i, j;
    for (i = 0; i < size; ++i) {
        _putchar(hex[(((unsigned char*)data)[i] >>  4) & 0xf]);
        _putchar(hex[((unsigned char*)data)[i] & 0xf]);
        //printf("%02X ", ((unsigned char*)data)[i]);
        if ((i+1) % 8 == 0 || i+1 == size) {
            print(" ");
            if ((i+1) % 16 == 0) {
                print("\n");
            } else if (i+1 == size) {
                if ((i+1) % 16 <= 8) {
                    print(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    print("   ");
                }
                print("\n");
            }
        }
    }
}

__attribute__ ((section(".text.main"))) int main() {

    hex_dump(0, 0x20000);

    // Reboot device, so we still get feedback in case the above didn't work
    wdt[8/4] = 0x1971;
    wdt[0/4] = 0x22000014;
    wdt[0x14/4] = 0x1209;

    while (1) {

    }

}
