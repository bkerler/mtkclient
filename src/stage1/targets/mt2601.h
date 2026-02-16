
#include <inttypes.h>
#define PAYLOAD_2_0    
char SOC_NAME[] = "mt2601";
    
void (*send_usb_response)(int, int, int) = (void*)0x406AC9;
int (*(*usbdl_ptr))() = (void*)0x40BA68;

const int mode=0;
volatile uint32_t **SEC_REG=(volatile uint32_t **)0x11141e80;
volatile uint32_t **SEC_REG2=(volatile uint32_t **)0x0;
volatile uint32_t SEC_OFFSET=0x40;
volatile uint32_t *bladdr=(volatile uint32_t *)0x11141f0c;
volatile uint32_t *bladdr2=(volatile uint32_t *)0x11144bc4;
volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x11005014;
volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x11005000;

int (*cmd_handler)() = (void*)0x40c5af;
            