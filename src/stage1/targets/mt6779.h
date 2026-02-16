
#include <inttypes.h>
#define PAYLOAD_2_0    
char SOC_NAME[] = "mt6779";
    
void (*send_usb_response)(int, int, int) = (void*)0x4cdb;
int (*(*usbdl_ptr))() = (void*)0xe04c;

const int mode=1;
volatile uint32_t **SEC_REG=(volatile uint32_t **)0x102acc;
volatile uint32_t **SEC_REG2=(volatile uint32_t **)0x1027b0;
volatile uint32_t SEC_OFFSET=0x28;
volatile uint32_t *bladdr=(volatile uint32_t *)0x102838;
volatile uint32_t *bladdr2=(volatile uint32_t *)0x106a60;
volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x11002014;
volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x11002000;

int (*cmd_handler)() = (void*)0xed6d;
            