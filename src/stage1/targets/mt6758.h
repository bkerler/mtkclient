
#include <inttypes.h>
#define PAYLOAD_2_0    
char SOC_NAME[] = "mt6758";
    
void (*send_usb_response)(int, int, int) = (void*)0x4937;
int (*(*usbdl_ptr))() = (void*)0xd860;

const int mode=1;
volatile uint32_t **SEC_REG=(volatile uint32_t **)0x102b8c;
volatile uint32_t **SEC_REG2=(volatile uint32_t **)0x1027ac;
volatile uint32_t SEC_OFFSET=0x28;
volatile uint32_t *bladdr=(volatile uint32_t *)0x102830;
volatile uint32_t *bladdr2=(volatile uint32_t *)0x106a60;
volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x11020014;
volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x11020000;

int (*cmd_handler)() = (void*)0xe58d;
            