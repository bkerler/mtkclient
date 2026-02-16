
#include <inttypes.h>
#define PAYLOAD_2_0    
char SOC_NAME[] = "mt6833";
    
void (*send_usb_response)(int, int, int) = (void*)0x48f3;
int (*(*usbdl_ptr))() = (void*)0xdfe0;

const int mode=1;
volatile uint32_t **SEC_REG=(volatile uint32_t **)0x102b0c;
volatile uint32_t **SEC_REG2=(volatile uint32_t **)0x1027bc;
volatile uint32_t SEC_OFFSET=0x28;
volatile uint32_t *bladdr=(volatile uint32_t *)0x102844;
volatile uint32_t *bladdr2=(volatile uint32_t *)0x106b54;
volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x11002014;
volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x11002000;

int (*cmd_handler)() = (void*)0xedad;
            