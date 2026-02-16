//(c) by B.Kerler, k4y0z 2021
#include <stdint.h>

//volatile uint32_t *wdt = (volatile uint32_t *)0x10007000;
volatile uint32_t *uart_base = (volatile uint32_t *)0x11002000;
volatile uint32_t SEC_ROFFSET2 = 0;
volatile uint32_t **SEC_REG2 = 0;
volatile uint32_t **SEC_REG = 0;
volatile uint32_t SEC_ROFFSET = 0;
volatile uint32_t SEC_OFFSET = 0x40;
volatile uint32_t fusebuffer[0x40/4] = {0};
volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x0;
volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x0;
//void (*send_usb_response)(int, int, int) = (void*)0x0;
uint32_t (*usbdl_put_data)() = (void*)0x0;
uint32_t (*usbdl_get_data)() = (void*)0x0;
uint32_t (*usbdl_put_word)() = (void*)0x0;
uint32_t (*cmd_handler)() = 0;

void low_uart_put(int ch) {
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

#ifdef DEBUG
void hex_dump(const void* data, uint32_t size) {
    static const char hex[] = "0123456789ABCDEF";
    uint32_t i, j;
    for (i = 0; i < size; ++i) {
        _putchar(hex[(((unsigned char*)data)[i] >>  4) & 0xf]);
        _putchar(hex[((unsigned char*)data)[i] & 0xf]);
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
#endif

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
    *Rt = (instr >> 8) & 7;
    uint32_t pc = (((uint32_t)curpc) / 4 * 4);
    return (uint32_t *)(pc + (imm8 * 4) + 4);
}

void ldr_imm(uint16_t instr, uint8_t *simm5, uint8_t *sRt, uint8_t *sRn) {
    *simm5 = (instr >> 6) & 0x1F;
    *sRt = (instr) & 0x7;
    *sRn = (instr >> 3) & 0x7;
}

void send_dword(uint32_t value){
    uint32_t ack=__builtin_bswap32(value);
    usbdl_put_data(&ack, 4);
}

__attribute__ ((section(".text.main"))) int main() {
    uint16_t instr = 0;
    uint16_t opcode = 0;
    uint8_t simm5;
    uint8_t sRt;
    uint8_t sRm;

    uint32_t offs1 = 0;
    uint32_t bromstart;
    uint32_t bromend;
    uint32_t startpos;

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

    bromstart = brom_base + 0x100;
    bromend = brom_base + 0x20000;

    //send_usb_response(1,0,1);
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
        }
    }
#ifdef DEBUG
    if ((int)usbdl_put_data == 1){
        print("F:upd\n");
        return 0;
    }
    else{
        print("A:upd\n");
        hex_dump(&usbdl_put_data, 4);
    }
#endif
#ifdef DEBUG
    if (!usbdl_get_data){
        print("F:ugd\n");
        return 0;
    }
    else{
        print("A:ugd\n");
        hex_dump(&usbdl_get_data, 4);
    }
#endif

    /* Time to find and set the watchdog before it's game over */
    uint8_t Rt = 0;
    /*static const uint16_t wdts[3] = {0xF641, 0x1071, 0x6088};
    offs1 = 0;
    offs1 = searchfunc(bromstart, bromend, wdts, 3);
    if (offs1) {
        wdt = (volatile uint32_t *)(ldr_lit((uint32_t)offs1 - 2, ((uint16_t*)(offs1 - 2))[0], &Rt)[0]);
        wdt[0] = 0x22000064;
#ifdef DEBUG
        print("A:WDT\n");
        hex_dump((void*)&wdt, 4);
#endif
    }
#ifdef DEBUG
    else {
        print("F:WDT\n");
    }
#endif*/

    /* Let's dance with send_usb_response */
    /*static const uint16_t sur1a[2] = {0xB530, 0x2300};
    static const uint16_t sur1b[3] = {0x2808, 0xD00F, 0x2807};
    static const uint16_t sur2[3] = {0x2400, 0xF04F, 0x5389};
    static const uint16_t sur3[3] = {0x2400, 0x2803, 0xD006};
    offs1 = searchfunc(bromstart, bromend, sur1a, 2);
    if (offs1) {
        startpos = searchfunc(offs1 + 6, offs1 + 12, sur1b, 3);
        if (startpos != offs1 + 6){
            offs1 = 0;
        }
    }
    if (!offs1) {
        offs1 = searchfunc(bromstart, bromend, sur2, 3);
        if (offs1){
            offs1 -= 2;
        } else {
            offs1 = searchfunc(bromstart, bromend, sur3, 3);
            if (offs1){
                offs1 -= 4;
            }
        }
    }
    if (offs1){
        send_usb_response = (void *)(offs1 | 1);
    }
#ifdef DEBUG
    if (offs1 == 0x0) {
        print("F:sur\n");
        return 0;
    }
    else{
        print("A:sur\n");
        hex_dump(&send_usb_response, 4);
    }
#endif
*/
    print("MTK-generic (c)bkerler/k4y0z 2021\n");
#ifdef DEBUG
    print("R:USB\n");
#endif
    //This is so we don't get a USB-Timeout
    //send_usb_response(1, 0, 1);
#ifdef DEBUG
    print("S:ACK\n");
#endif
    static const uint32_t ack = 0xA4A3A2A1;
    usbdl_put_data(&ack, 4);

    /* sbc to go, please .... */
    static const uint16_t sbcr[1] = {0xB510};
    uint32_t sbc = 0;
    offs1 = -1;
    startpos = bromstart;
    while (offs1){
        offs1 = searchfunc(startpos, bromend, sbcr, 1);
        uint8_t* posc = (uint8_t *)offs1;
        if (((uint8_t)posc[3] == (uint8_t)0xF0) && (((uint8_t)posc[7] == (uint8_t)0x46) || ((uint8_t)posc[7] == (uint8_t)0x49))){
                sbc = (uint32_t)offs1;
                break;
            }
        startpos = offs1 + 2;
    }
#ifdef DEBUG
    if (!sbc){
        print("F:sbc");
        return 0;
    }
    else{
        print("A:sbc\n");
        hex_dump(&sbc, 4);
    }
#endif

    /* search for security 0 .... */
    int8_t mode = -1;
    uint32_t offset = 0;
    int i = 0;
    Rt = 0;
    for (i = 0; i < 0x100; i += 2) {
        instr = ((uint16_t*)((uint32_t)sbc + i))[0];
        opcode = ((instr >> 11) & 0x1F);
        if (opcode == 9){
            offset = ldr_lit((uint32_t)sbc + i, instr, &Rt)[0];
            SEC_ROFFSET = offset;
        }
        if (SEC_ROFFSET != 0){
            if (opcode == 0xD){
                // LDR (Immediate), LDR R1, [R1, #SEC_OFFSET]
                ldr_imm(instr, &simm5, &sRt, &sRm);
                if (Rt == sRt && simm5){
                    SEC_OFFSET = (uint32_t)simm5 * 4;
                    if (SEC_OFFSET == 0x40){
                        mode = 0;
                        break;
                    }
                    else {
                        SEC_ROFFSET += SEC_OFFSET;
                    }
                    
                }
            }
            else if (instr == 0x1040)
            {
                mode = 0;
                break;
            }
            else if (instr == 0x10BD)
            {
                break;
            }

        }
    }

    /* search for security 1 */
    offs1 = 0;
    if (mode){
        SEC_ROFFSET = 0;
        uint32_t sbc_intern = (uint32_t)(sbc - 0xE);
        for (i = 0; i < 0x20; i += 2){
            instr = ((uint16_t*)((uint32_t)sbc_intern + i))[0];
            opcode = ((instr >> 11) & 0x1F);
            if (opcode == 9){
                offset = ldr_lit((uint32_t)sbc_intern + i, instr, &Rt)[0];
                SEC_ROFFSET = offset;
            }
            if (SEC_ROFFSET) {
                if (opcode == 0xD) {
                    // LDR (Immediate), LDR R1, [R1, #SEC_OFFSET]
                    ldr_imm(instr, &simm5, &sRt, &sRm);
                    if (sRm == Rt){
                        if (!offs1){
                            SEC_ROFFSET = offset + (simm5 * 4);
                            SEC_OFFSET = 0x28;
                            mode = 1;
                            break;
                        }
                        offs1++;
                    }
                }
            }
        }
    }

    if (mode==1){
        offs1 = -1;
        startpos = bromstart;
        while (offs1){
            offs1 = searchfunc(startpos, bromend, sbcr, 1);
            uint8_t* posc = (uint8_t *)offs1;
            if (((uint8_t)posc[3] == (uint8_t)0x20) && ((uint8_t)posc[9] == (uint8_t)0x49)) {
                    SEC_ROFFSET2 = (uint32_t)offs1;
                    instr = ((uint16_t*)((uint32_t)(offs1+8)))[0];
                    SEC_ROFFSET2=ldr_lit(offs1+8,instr, &Rt)[0];
                    break;
            }

            startpos = offs1 + 2;
        }
    }
#ifdef DEBUG
    print("S:ACK2\n");
#endif

    if (mode == -1){
        usbdl_put_data(&mode, 4);
    }
    else {
        usbdl_put_data(&ack, 4);
    }
#ifdef DEBUG
    print("A:mode\n");
    hex_dump((void *)&mode, 4);
    print("A:SEC_ROFFSET\n");
    hex_dump((void *)&SEC_ROFFSET, 4);
    print("A:SEC_ROFFSET2\n");
    hex_dump((void *)&SEC_ROFFSET2, 4);
    print("fusebuffer\n");
#endif

    SEC_REG = (volatile uint32_t **)SEC_ROFFSET;
    SEC_REG2 = (volatile uint32_t **)SEC_ROFFSET2;
    fusebuffer[0] = 0x1;

    if (mode==0) {
        *SEC_REG = (volatile uint32_t *)&fusebuffer; // 1026D4, !=0 (SLA, SBC)
        fusebuffer[SEC_OFFSET/4] = 0xB; // 1026D4+0x40, << 0x1e < 0x0 (DAA),  & << 0x1f !=0 (SLA), << 0x1c < 0x0 (SBC)
    }
    else if (mode==1)
    {
        *((volatile uint32_t *)(SEC_REG)) = 0x1;
        *((volatile uint32_t *)(SEC_REG + 2)) = 0xB;
        *SEC_REG2 = (volatile uint32_t *)&fusebuffer; // 1026D4, !=0 (SLA, SBC)
        fusebuffer[SEC_OFFSET/4] = 0x700; // 1026D4+0x40, << 0x1e < 0x0 (DAA),  & << 0x1f !=0 (SLA), << 0x1c < 0x0 (SBC)
    }

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

    //invalidate icache
    asm volatile ("mcr p15, 0, %0, c7, c5, 0" : : "r" (0));

    const char sequence[] = {0xA0, 0x0A, 0x50, 0x05};
    offs1 = 0;
    sRt = 0;

#ifdef DEBUG
    print("W:HSK\n");
#endif
    do {
        while ( ((*uart_reg0) & 1) ) {}
        while ( 1 ) {
            usbdl_get_data(&sRt, 1);
            if(sequence[offs1] == sRt) break;
            offs1 = 0;
            print("\nF:HSK\n");
        }
        sRt = ~sRt;
        usbdl_put_data(&sRt, 1);
        offs1 += 1;
        print(".");
    } while(offs1 != 4);

    print("\nA:HSK\n");
 
    return cmd_handler();
}
