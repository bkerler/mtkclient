#!/bin/bash
for i in $(find ./bootrom -name "*.bin"|sort);do ./mtkclient/Tools/brom_to_offs "$i";done
