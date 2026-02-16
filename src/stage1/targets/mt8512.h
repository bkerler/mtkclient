
#include <inttypes.h>
#define PAYLOAD_2_0    
char SOC_NAME[] = "mt8512";
    
void (*send_usb_response)(int, int, int) = (void*)0x6697;
int (*(*usbdl_ptr))() = (void*)0xCC44;

const int mode=1;
volatile uint32_t **SEC_REG=(volatile uint32_t **)0x1045CC;
volatile uint32_t **SEC_REG2=(volatile uint32_t **)0x104178;
volatile uint32_t SEC_OFFSET=0x28;
volatile uint32_t *bladdr=(volatile uint32_t *)0x1041E4;
volatile uint32_t *bladdr2=(volatile uint32_t *)0x10AA84;
volatile uint32_t *uart_reg0 = (volatile uint32_t*)0x11002014;
volatile uint32_t *uart_reg1 = (volatile uint32_t*)0x11002000;

int (*cmd_handler)() = (void*)0xD7AB;
            