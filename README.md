# IDA-scripts

Useful scripts for IDA

## STM32

Scripts for STM32 microcotrollers family

### ida_stm32f1xx.py

Basic transformations on disassembled STM32 flash binaries:
* Create Interrupt Vector Table
* Create Entrypoint
* Create SRAM segment
* Create commented Register's data (as Enumerations)

```
Usage example

* Open STM32F1xx binary in IDA
* in 'Processor Options' select: ARMv7-M (Thumb-2, ARM instructions NO)
* Press OK
* Press ALT + F7 (or File -> Script file) then select this script
```