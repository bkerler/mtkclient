
#include <inttypes.h>
#define PAYLOAD_2_0    
char SOC_NAME[] = "mt8695";
    
void (*send_usb_response)(int, int, int) = (void*)0x55bb;
int (*(*usbdl_ptr))() = (void*)0xbeec;

const int mode=0;
volatile uint32_t **SEC_REG=(volatile uint32_t **)0x102fbc;
volatile uint32_t **SEC_REG2=(volatile uint32_t **)0x0;
volatile uint32_t SEC_OFFSET=0x40;
volatile uint32_t *bladdr=(volatile uint32_t *)0x103048;
volatile uint32_t *bladdr2=(volatile uint32_t *)0x106ec4;
volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x11003014;
volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x11003000;

int (*cmd_handler)() = (void*)0xcaa7;
            