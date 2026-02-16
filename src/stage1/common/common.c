// (c) 2021 by bkerler, k4y0z
#define _STRINGIFY(str) #str
#define STRINGIFY(str) _STRINGIFY(str)

#ifdef DEVICE_HEADER
#include STRINGIFY(DEVICE_HEADER)
#endif

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

volatile uint32_t fusebuffer[0x40/4] = {0};

__attribute__ ((section(".text.main"))) int main() {

#ifdef PAYLOAD_2_0
    //Fix ptr_send
    *(volatile uint32_t *)(usbdl_ptr[0] + 8) = (uint32_t)usbdl_ptr[2];

    int (*usbdl_get_data)() = usbdl_ptr[1];

    int usbdl_put_data(void* data, uint32_t size) {;
        (usbdl_ptr[2])(data, size);
        return (usbdl_ptr[3])();
    }

#define CMD_HANDLER cmd_handler()
#else
#define CMD_HANDLER 0
#endif

    print("Entered ");
    print(SOC_NAME);
    print(" brom patcher\n");

    print("Copyright k4y0z/bkerler 2021\n");

    //This is so we don't get a USB-Timeout
    print("R:USB\n");
    send_usb_response(1,0,1);

    print("S:ACK\n");
    uint32_t ack=0xA4A3A2A1;
    usbdl_put_data(&ack,4);

    if (mode==0) {
        fusebuffer[0] = 0x1;
        fusebuffer[SEC_OFFSET/4] = 0xB; // 1026D4+0x40, << 0x1e < 0x0 (DAA),  & << 0x1f !=0 (SLA), << 0x1c < 0x0 (SBC)
        *SEC_REG = (volatile uint32_t *)&fusebuffer; // 1026D4, !=0 (SLA, SBC)
    }
    else if (mode==1)
    {
        fusebuffer[SEC_OFFSET/4] = 0x700; // 1026D4+0x40, << 0x1e < 0x0 (DAA),  & << 0x1f !=0 (SLA), << 0x1c < 0x0 (SBC)
        *((volatile uint32_t *)(SEC_REG + 2)) = 0xB;
        *SEC_REG2 = (volatile uint32_t *)&fusebuffer; // 1026D4, !=0 (SLA, SBC)
        *SEC_REG = (volatile uint32_t *)&fusebuffer; // 1026D4, !=0 (SLA, SBC)
    }

    if (bladdr)
    {
        *bladdr=0;
    }

    if (bladdr2)
    {
        *bladdr2=0;
    }

    //invalidate icache
    asm volatile ("mcr p15, 0, %0, c7, c5, 0" : : "r" (0));

    const char sequence[] = {0xA0, 0x0A, 0x50, 0x05};
    unsigned int index = 0;
    unsigned char hs = 0;

    print("W:Handshake\n");
    do {
        while ( ((*uart_reg0) & 1) ) {}
        while ( 1 ) {
            usbdl_get_data(&hs, 1);
            if(sequence[index] == hs) break;
            index = 0;
            print("\nF:Handshake\n");
        }
        hs = ~hs;
        usbdl_put_data(&hs, 1);
        index += 1;
        print(".");
    } while(index != 4);

    print("\nA:Handshake\n");

    return CMD_HANDLER;
}
