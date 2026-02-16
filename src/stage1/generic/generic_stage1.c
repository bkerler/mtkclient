//(c) by B.Kerler, k4y0z 2021
#include <stdint.h>

volatile uint32_t *wdt = (volatile uint32_t *)0x10007000;
volatile uint32_t *uart_base = (volatile uint32_t *)0x11002000;
volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x0;
volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x0;
void (*send_usb_response)(int, int, int) = (void*)0x0;
int (*usbdl_put_data)() = (void*)0x0;
int (*usbdl_get_data)() = (void*)0x0;
uint32_t (*usbdl_put_word)() = (void*)0x0;

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

void send_dword(uint32_t value){
    uint32_t ack=__builtin_bswap32(value);
    usbdl_put_data(&ack, 4);
}

uint32_t recv_dword(){
    uint32_t value;
    usbdl_get_data(&value,4);
    return __builtin_bswap32(value);
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

#if DEBUG
static const char hex[] = "0123456789ABCDEF";
void pdword(uint32_t value)
{
   int i;
   _putchar(0x30);
   _putchar(0x78);
   for (i=3;i>=0;i--){
        _putchar(hex[(((value>>(i*8))&0xFF) >>  4) & 0xf]);
        _putchar(hex[((value>>(i*8))&0xFF) & 0xf]);
   }
}
/*
static inline uint32_t get_ttbr0(void)
{
	uint32_t ttbr0;

	asm volatile ("mrc	p15, 0, %[ttbr0], c2, c0, 0"
			: [ttbr0] "=r" (ttbr0)
	);

	return ttbr0;
}

static inline uint32_t get_ttbr1(void)
{
	uint32_t ttbr1;

	asm volatile ("mrc	p15, 0, %[ttbr1], c2, c0, 1"
			: [ttbr1] "=r" (ttbr1)
	);

	return ttbr1;
}

static inline uint64_t get_ttbr0_64bit(void)
{
	uint64_t ttbr0;
	asm volatile ("mrrc	p15, 0, %Q[ttbr0], %R[ttbr0], c2"
			: [ttbr0] "=r" (ttbr0)
	);
	return ttbr0;
}
*/

void hex_dump(const void* data, uint32_t size) {
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

/*
void apmcu_icache_invalidate(){
    asm volatile ("mcr p15, 0, %0, c7, c5, 0" :: "r"(0));
}

void apmcu_isb(){
    asm volatile ("ISB");
}

void apmcu_disable_icache(){
    uint32_t r0=0;
    asm volatile ("mcr p15, 0, %0, c7, c5, 6" :: "r"(r0)); // Flush entire branch target cache
    asm volatile ("mrc p15, 0, %0, c1, c0, 0" : "=r"(r0));
    asm volatile ("bic %0,%0,#0x1800" : "=r"(r0) : "r"(r0)); // I+Z bits
    asm volatile ("mcr p15, 0, %0, c1, c0, 0" :: "r"(r0));
}

void apmcu_disable_smp(){
    uint32_t r0=0;
    asm volatile ("mrc p15, 0, %0, c1, c0, 1" : "=r"(r0));
    asm volatile ("bic %0,%0,#0x40" : "=r"(r0) : "r"(r0)); // SMP bit
    asm volatile ("mcr p15, 0, %0, c1, c0, 1" :: "r"(r0));
}


*/
/*typedef struct {
    uint32_t magic;
    uint32_t ver;
    uint32_t flags;
} DownloadArg;
*/

__attribute__ ((section(".text.main"))) int main() {
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
    bromend = brom_base + 0x14000;

    /* Time to find and set the watchdog before it's game over */
    static const uint16_t wdts[3] = {0xF641, 0x1071, 0x6088};
    uint8_t Rt = 0;
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
#endif

    /* Let's dance with send_usb_response */
    static const uint16_t sur1a[2] = {0xB530, 0x2300};
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

    print("(c) bkerler/k4y0z\n");
#ifdef DEBUG
    print("R:USB\n");
#endif
    //This is so we don't get a USB-Timeout
    send_usb_response(1, 0, 1);
#ifdef DEBUG
    print("S:ACK\n");
    print("Hi :)\n");
#endif
    send_dword(0xA1A2A3A4);
    while (1) {
        print("WAIT\n");
        uint32_t magic = recv_dword();
#ifdef DEBUG
        hex_dump(&magic,4);
#endif
        if (magic != 0xf00dd00d) {
            print("ERR\n");
            #ifdef DEBUG
                hex_dump(&magic,4);
            #endif
            //printf("Magic received = 0x%08X\n", magic);
            break;
        }
        uint32_t cmd = recv_dword();
        uint32_t jump_addr=0;
        switch (cmd) {
        case 0x4000: {
            uint32_t address = recv_dword();
            uint32_t size = recv_dword();
            #ifdef DEBUG
                print("Write ");
                pdword(size);
                print(" bytes to address ");
                pdword(address);
                print("\n");
            #endif
            if(usbdl_get_data((unsigned char*)address, size) == 0) {
                print("OK\n");
                send_dword(0xD0D0D0D0);
                //hex_dump((void *)address, size);
            } else {
                send_dword(0xF0F0F0F0);
                print("F\n");
            }
            break;
        }
        case 0x4001: {
            jump_addr=recv_dword();
            void (*jump)(int) = (void*) jump_addr;
            #ifdef DEBUG
                print("Jump to ");
                pdword(jump_addr);
                print("\n");
            #endif
            print("JMP\n");
            /*apmcu_icache_invalidate();
            apmcu_disable_icache();
            apmcu_isb();
            apmcu_disable_smp();*/

            /*DownloadArg *da_arg;
            da_arg = (DownloadArg*)(0x0010DC00 - sizeof(DownloadArg)); // CFG_DA_RAM_ADDR 0x10DC00 or 0x402000000
            da_arg->magic = 0x58885168;
            da_arg->ver   = 1;
            da_arg->flags = 1|2; //DA_FLAG_SKIP_PLL_INIT | DA_FLAG_SKIP_EMI_INIT;
            */
            //MOV r4, r1   /* r4 argument */ init.s
            //MOV r5, r2   /* r5 argument */
            //MOV pc, r0    /* jump to addr */
            //MOV r7, r3   /* r3 = TEE boot entry, relocate to r7 */
            /*asm volatile("mov r5, %0\n"
                        "mov r4, %1\n"
                        "mov r3, %2\n"
                        "blx r3\n"
                        : : "r"((uint32_t)sizeof(DownloadArg)), "r"((uint32_t)da_arg), "r"(jump_addr) : "r5", "r4", "r3");
            */
            jump(0);
            break;
        }
        /*case 0x4002: {
            print("RD\n");
            uint32_t address = recv_dword();
            uint32_t size = recv_dword();
            #ifdef DEBUG
            pdword(size);
            print(" bytes from address ");
            pdword(address);
            print("\n");
            #endif
            uint32_t ssize=64;
            uint32_t m=0;
            while ((int)size>0){
                if (size<64) ssize=size;
                usbdl_put_data((unsigned char*)address+m,ssize);
                size-=ssize;
                m+=ssize;
            }
            //send_dword(0xD0D0D0D0);
            break;
        }*/
        case 0x3000: {
            print("RB\n");
            volatile uint32_t *reg = (volatile uint32_t *)wdt;
            reg[8/4] = 0x1971;
            reg[0/4] = 0x22000014;
            reg[0x14/4] = 0x1209;
            while (1) {

            }
        }
        case 0x3001: {
            print("WDT\n");
            volatile uint32_t *reg = (volatile uint32_t *)wdt;
            reg[8/4] = 0x1971;
            break;
        }
        default:
            print("INV\n");
            break;
        }
    }
    #ifdef DEBUG
    print("EXIT\n");
    #endif
    while (1) {
    }
}
