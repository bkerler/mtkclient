.syntax unified

.code 32

.global start
.section .text.start
start:
    add r3, pc, #1
    bx r3
