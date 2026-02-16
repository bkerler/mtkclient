// (c) 2021 by k4y0z
#include <stdint.h>

volatile uint32_t *wdt = (volatile uint32_t *)0x10007000;

int main() {
    wdt[8/4] = 0x1971;
    wdt[0/4] = 0x22000014;
    wdt[0x14/4] = 0x1209;

    while (1) {

    }
}
