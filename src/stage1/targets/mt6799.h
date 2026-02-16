
#include <inttypes.h>
#define PAYLOAD_2_0    
char SOC_NAME[] = "mt6799";
    
void (*send_usb_response)(int, int, int) = (void*)0x66af;
int (*(*usbdl_ptr))() = (void*)0xf5ac;

const int mode=1;
volatile uint32_t **SEC_REG=(volatile uint32_t **)0x10334c;
volatile uint32_t **SEC_REG2=(volatile uint32_t **)0x1027ec;
volatile uint32_t SEC_OFFSET=0x28;
volatile uint32_t *bladdr=(volatile uint32_t *)0x102870;
volatile uint32_t *bladdr2=(volatile uint32_t *)0x107070;
volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x11020014;
volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x11020000;

int (*cmd_handler)() = (void*)0x102c3;
            