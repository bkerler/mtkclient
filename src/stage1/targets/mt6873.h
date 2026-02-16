
#include <inttypes.h>
#define PAYLOAD_2_0    
char SOC_NAME[] = "mt6873";
    
void (*send_usb_response)(int, int, int) = (void*)0x53af;
int (*(*usbdl_ptr))() = (void*)0xea78;

const int mode=1;
volatile uint32_t **SEC_REG=(volatile uint32_t **)0x102b0c;
volatile uint32_t **SEC_REG2=(volatile uint32_t **)0x1027c4;
volatile uint32_t SEC_OFFSET=0x28;
volatile uint32_t *bladdr=(volatile uint32_t *)0x10284c;
volatile uint32_t *bladdr2=(volatile uint32_t *)0x106b60;
volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x11002014;
volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x11002000;

int (*cmd_handler)() = (void*)0xf7fd;
            