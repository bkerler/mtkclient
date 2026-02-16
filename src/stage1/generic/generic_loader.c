// Copyright 2021 k4y0z, bekrler

#include <stdint.h>
void (*(*usbdl_ptr))() = (void *)0xDEADBEEF;

int main() {
    *(volatile uint32_t *)(usbdl_ptr[0] + 8) = (uint32_t)usbdl_ptr[2];
    void (*usbdl_get_data)() = usbdl_ptr[1];
    void (*usbdl_put_data)() = usbdl_ptr[2];
    void (*usbdl_flush_data)() = usbdl_ptr[3];

    usbdl_put_data(&usbdl_ptr, 4);
    usbdl_flush_data();

    uint32_t size;
    void (*address)();

    usbdl_get_data(&address, 4);
    usbdl_get_data(&size, 4);

    usbdl_get_data(address, size);

    address();
}