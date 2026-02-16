
#include <inttypes.h>
#define PAYLOAD_2_0    
char SOC_NAME[] = "mt8168";
    
void (*send_usb_response)(int, int, int) = (void*)0xD0F3;
int (*(*usbdl_ptr))() = (void*)0x13834;

const int mode=0;
volatile uint32_t **SEC_REG=(volatile uint32_t **)0x1063CC;
volatile uint32_t **SEC_REG2=(volatile uint32_t **)0x0;
volatile uint32_t SEC_OFFSET=0x8;
volatile uint32_t *bladdr=(volatile uint32_t *)0x10303C;
volatile uint32_t *bladdr2=(volatile uint32_t *)0x10A540;
volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x11002014;
volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x11002000;

int (*cmd_handler)() = (void*)0x1436F;
            