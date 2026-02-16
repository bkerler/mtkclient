
#include <inttypes.h>
#define PAYLOAD_2_0    
char SOC_NAME[] = "mt8167";
    
void (*send_usb_response)(int, int, int) = (void*)0x6c7d;
int (*(*usbdl_ptr))() = (void*)0xd2e4;

const int mode=1;
volatile uint32_t **SEC_REG=(volatile uint32_t **)0x10340c;
volatile uint32_t **SEC_REG2=(volatile uint32_t **)0x1028e4;
volatile uint32_t SEC_OFFSET=0x28;
volatile uint32_t *bladdr=(volatile uint32_t *)0x102968;
volatile uint32_t *bladdr2=(volatile uint32_t *)0x107954;
volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x11005014;
volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x11005000;

int (*cmd_handler)() = (void*)0xdff7;
            