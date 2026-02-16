
#include <inttypes.h>
#define PAYLOAD_2_0    
char SOC_NAME[] = "mt6575";
    
void (*send_usb_response)(int, int, int) = (void*)0xffff4e2b;
int (*(*usbdl_ptr))() = (void*)0xffffa0a0;

const int mode=0;
volatile uint32_t **SEC_REG=(volatile uint32_t **)0xf0002538;
volatile uint32_t **SEC_REG2=(volatile uint32_t **)0x0;
volatile uint32_t SEC_OFFSET=0x40;
volatile uint32_t *bladdr=(volatile uint32_t *)0xf00025c4;
volatile uint32_t *bladdr2=(volatile uint32_t *)0xf00051e4;
volatile uint32_t *uart_reg0 = (volatile uint32_t*)0xc1009014;
volatile uint32_t *uart_reg1 = (volatile uint32_t*)0xc1009000;

int (*cmd_handler)() = (void*)0xffffad5d;
            