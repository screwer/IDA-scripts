'''
IDA script for STM32F1xx family microcontrollers.

Written by Artamonov Dmitry <screwer@gmail.com>

This program is free software. It comes without any warranty, to the extent permitted by applicable law.
You can redistribute it and/or modify it under the terms of the WTFPL, Version 2, as published by Sam Hocevar.
See http://www.wtfpl.net/ for more details
'''

#import idaapi
import sys
import operator

#-------------------------------------------------------------------

def KB(n):
    return n * 1024

#-------------------------------------------------------------------
#
# STM32F103RET6
#
# Processor options -> ARM LittleEndian -> No automatic Thumb switch -> ARMv7-M (Thumb-2, ARM instructions NO)
# Options -> Disassembly: Number Of Opcode bytes = 4, Instruction indentation = 32
#
class Features:

    FlashSize       = KB(512)
    SRamSize        = KB(64)
    VecTableSize    = 0x12C

    Peripherals = [
        'RCC',  'RTC',  'PWR',  'CRC',
        'EXTI', 'IWDG', 'WWDG', 'FLASH',

        'SPI1', 'SPI2',
        'I2C1', 'I2C2',
        'ADC1', 'ADC2', #'ADC3',
        'TIM1', 'TIM2', 'TIM3', 'TIM4', #'TIM5', 'TIM6', 'TIM7', 'TIM8', 'TIM9', 'TIM10', 'TIM11', 'TIM12', 'TIM13', 'TIM14',
        'CAN1', # 'CAN2',
        'USB',
    ]

#-------------------------------------------------------------------

def dump(obj, nested_level=0, output=sys.stdout):
    spacing = '   '
    if type(obj) == dict:
        print >> output, '%s{' % ((nested_level) * spacing)
        for k, v in obj.items():
            if hasattr(v, '__iter__'):
                print >> output, '%s%s:' % ((nested_level + 1) * spacing, k)
                dump(v, nested_level + 1, output)
            else:
                print >> output, '%s%s: %s' % ((nested_level + 1) * spacing, k, v)
        print >> output, '%s}' % (nested_level * spacing)
    elif type(obj) == list:
        print >> output, '%s[' % ((nested_level) * spacing)
        for v in obj:
            if hasattr(v, '__iter__'):
                dump(v, nested_level + 1, output)
            else:
                print >> output, '%s%s' % ((nested_level + 1) * spacing, v)
        print >> output, '%s]' % ((nested_level) * spacing)
    else:
        print >> output, '%s%s' % (nested_level * spacing, obj)

#-------------------------------------------------------------------

def RoundUpPow2(v):
    v -= 1
    v |= (v >> 1)
    v |= (v >> 2)
    v |= (v >> 4)
    v |= (v >> 8)
    v |= (v >> 16)
    v += 1
    return v

#-------------------------------------------------------------------
#
# Memory map for all buses
#
FLASH_BASE          = 0x08000000
PERIPH_BASE         = 0x40000000
INFO_BASE           = 0x1ffff000
PERIPH_BASE_APB1    = (PERIPH_BASE + 0x00000)
PERIPH_BASE_APB2    = (PERIPH_BASE + 0x10000)
PERIPH_BASE_AHB     = (PERIPH_BASE + 0x18000)
#
# APB1
#
TIM2_BASE           = (PERIPH_BASE_APB1 + 0x0000)
TIM3_BASE           = (PERIPH_BASE_APB1 + 0x0400)
TIM4_BASE           = (PERIPH_BASE_APB1 + 0x0800)
TIM5_BASE           = (PERIPH_BASE_APB1 + 0x0c00)
TIM6_BASE           = (PERIPH_BASE_APB1 + 0x1000)
TIM7_BASE           = (PERIPH_BASE_APB1 + 0x1400)
TIM12_BASE          = (PERIPH_BASE_APB1 + 0x1800)
TIM13_BASE          = (PERIPH_BASE_APB1 + 0x1c00)
TIM14_BASE          = (PERIPH_BASE_APB1 + 0x2000)
RTC_BASE            = (PERIPH_BASE_APB1 + 0x2800)
WWDG_BASE           = (PERIPH_BASE_APB1 + 0x2c00)
IWDG_BASE           = (PERIPH_BASE_APB1 + 0x3000)
SPI2_BASE           = (PERIPH_BASE_APB1 + 0x3800)
SPI3_BASE           = (PERIPH_BASE_APB1 + 0x3c00)
USART2_BASE         = (PERIPH_BASE_APB1 + 0x4400)
USART3_BASE         = (PERIPH_BASE_APB1 + 0x4800)
UART4_BASE          = (PERIPH_BASE_APB1 + 0x4c00)
UART5_BASE          = (PERIPH_BASE_APB1 + 0x5000)
I2C1_BASE           = (PERIPH_BASE_APB1 + 0x5400)
I2C2_BASE           = (PERIPH_BASE_APB1 + 0x5800)
USB_DEV_FS_BASE     = (PERIPH_BASE_APB1 + 0x5c00)
USB_PMA_BASE        = (PERIPH_BASE_APB1 + 0x6000)
USB_CAN_SRAM_BASE   = (PERIPH_BASE_APB1 + 0x6000)
BX_CAN1_BASE        = (PERIPH_BASE_APB1 + 0x6400)
BX_CAN2_BASE        = (PERIPH_BASE_APB1 + 0x6800)
BACKUP_REGS_BASE    = (PERIPH_BASE_APB1 + 0x6c00)
POWER_CONTROL_BASE  = (PERIPH_BASE_APB1 + 0x7000)
DAC_BASE            = (PERIPH_BASE_APB1 + 0x7400)
CEC_BASE            = (PERIPH_BASE_APB1 + 0x7800)
#
# APB2
#
AFIO_BASE           = (PERIPH_BASE_APB2 + 0x0000)
EXTI_BASE           = (PERIPH_BASE_APB2 + 0x0400)
GPIO_PORT_A_BASE    = (PERIPH_BASE_APB2 + 0x0800)
GPIO_PORT_B_BASE    = (PERIPH_BASE_APB2 + 0x0c00)
GPIO_PORT_C_BASE    = (PERIPH_BASE_APB2 + 0x1000)
GPIO_PORT_D_BASE    = (PERIPH_BASE_APB2 + 0x1400)
GPIO_PORT_E_BASE    = (PERIPH_BASE_APB2 + 0x1800)
GPIO_PORT_F_BASE    = (PERIPH_BASE_APB2 + 0x1c00)
GPIO_PORT_G_BASE    = (PERIPH_BASE_APB2 + 0x2000)
ADC1_BASE           = (PERIPH_BASE_APB2 + 0x2400)
ADC2_BASE           = (PERIPH_BASE_APB2 + 0x2800)
TIM1_BASE           = (PERIPH_BASE_APB2 + 0x2c00)
SPI1_BASE           = (PERIPH_BASE_APB2 + 0x3000)
TIM8_BASE           = (PERIPH_BASE_APB2 + 0x3400)
USART1_BASE         = (PERIPH_BASE_APB2 + 0x3800)
ADC3_BASE           = (PERIPH_BASE_APB2 + 0x3c00)
TIM15_BASE          = (PERIPH_BASE_APB2 + 0x4000)
TIM16_BASE          = (PERIPH_BASE_APB2 + 0x4400)
TIM17_BASE          = (PERIPH_BASE_APB2 + 0x4800)
TIM9_BASE           = (PERIPH_BASE_APB2 + 0x4c00)
TIM10_BASE          = (PERIPH_BASE_APB2 + 0x5000)
TIM11_BASE          = (PERIPH_BASE_APB2 + 0x5400)
#
# AHB
#
SDIO_BASE           = (PERIPH_BASE_AHB + 0x00000)
DMA1_BASE           = (PERIPH_BASE_AHB + 0x08000)
DMA2_BASE           = (PERIPH_BASE_AHB + 0x08400)
RCC_BASE            = (PERIPH_BASE_AHB + 0x09000)
FLASH_MEM_INTERFACE_BASE = (PERIPH_BASE_AHB + 0x0a000)
CRC_BASE            = (PERIPH_BASE_AHB + 0x0b000)
ETHERNET_BASE       = (PERIPH_BASE_AHB + 0x10000)
USB_OTG_FS_BASE     = (PERIPH_BASE_AHB + 0xffe8000)
#
# PPBI
#
PPBI_BASE           = 0xE0000000            # Private peripheral bus - Internal
ITM_BASE            = (PPBI_BASE + 0x0000)  # ITM: Instrumentation Trace Macrocell
DWT_BASE            = (PPBI_BASE + 0x1000)  # DWT: Data Watchpoint and Trace unit
FPB_BASE            = (PPBI_BASE + 0x2000)  # FPB: Flash Patch and Breakpoint unit

DBGMCU_BASE         = (PPBI_BASE + 0x00042000)
TPIU_BASE           = (PPBI_BASE + 0x40000)
    #
    # TPIU registers
    #
    # 0xE0040004 - Current port size
    # 0xE00400F0 - Selected pin protocol
    # 0xE0040304 - Formatter and flush control
    # 0xE0040300 - Formatter and flush status (Not used in Cortex-M3, always read as 0x00000008)
    #
#
# SCS: System Control Space
#
SCS_BASE            = (PPBI_BASE + 0xE000)
ITR_BASE            = (SCS_BASE + 0x0000)   # ITR: Interrupt Type Register
SYS_TICK_BASE       = (SCS_BASE + 0x0010)   # SYS_TICK: System Timer
NVIC_BASE           = (SCS_BASE + 0x0100)   # NVIC: Nested Vector Interrupt Controller
SCB_BASE            = (SCS_BASE + 0x0D00)   # SCB: System Control Block
MPU_BASE            = (SCS_BASE + 0x0D90)   # MPU: Memory protection unit
STIR_BASE           = (SCS_BASE + 0x0F00)   # STE: Software Trigger Interrupt Register
ID_BASE             = (SCS_BASE + 0x0FD0)   # ID: ID space

#
# FSMC
#
FSMC_BASE           = (PERIPH_BASE +  0x60000000)
#
# Device Electronic Signature
#
DESIG_FLASH_SIZE_BASE= (INFO_BASE + 0x7e0)

DESIG_UNIQUE_ID_BASE = (INFO_BASE + 0x7e8)
    #
    # 96-bits register
    #
    # Offset: 0x00, R/O 0xXXXX
    # Offset: 0x02, R/O 0xXXXX
    # Offset: 0x04, R/O 0xXXXXXXXX
    # Offset: 0x08, R/O 0xXXXXXXXX
    #
DESIG_UNIQUE_ID0     = (DESIG_UNIQUE_ID_BASE)
DESIG_UNIQUE_ID1     = (DESIG_UNIQUE_ID_BASE + 4)
DESIG_UNIQUE_ID2     = (DESIG_UNIQUE_ID_BASE + 8)

#-------------------------------------------------------------------
#
# SCB: System Control State
#
#-------------------------------------------------------------------
#
# ITR: Interrupt Type Register
#
REGS_ITR    = { 'BASE': 0x0000, }

#-------------------------------------------------------------------
#
# SYS_TICK: System Timer
#
REGS_SYS_TICK={ 'CSR':      (0x00, 'Control and status register (STK_CTRL)'),
                'RVR':      (0x04, 'reload value register (STK_LOAD)'),
                'CVR':      (0x08, 'current value register (STK_VAL)'),
                'CALIB':    (0x0C, 'calibration value register (STK_CALIB)'),
            }

#-------------------------------------------------------------------
#
# NVIC: Nested Vector Interrupt Controller
#
REGS_NVIC   = {}

for n in range(0, 7 + 1):
    REGS_NVIC['ISER%d' % n] = (0x00  + (4 * n), 'ISER: Interrupt Set Enable Registers')
    REGS_NVIC['ICER%d' % n] = (0x80  + (4 * n), 'ICER: Interrupt Clear Enable Registers')
    REGS_NVIC['ISPR%d' % n] = (0x100 + (4 * n), 'ISPR: Interrupt Set Pending Registers')
    REGS_NVIC['ICPR%d' % n] = (0x180 + (4 * n), 'ICPR: Interrupt Clear Pending Registers')
    REGS_NVIC['IABR%d' % n] = (0x200 + (4 * n), 'ICPR: Interrupt Active Bit Registers')
for n in range(0, 240):
    REGS_NVIC['IPR%02x' % n] = (0x300 + (4 * n), 'IPR: Interrupt Priority Registers')

#-------------------------------------------------------------------
#
# SCB: System Control Block
#
REGS_SCB    = { 'CPIID':        (0x00, 'CPUID: CPUID base register'),
                'ICSR':         (0x04, 'ICSR: Interrupt Control State Register'),
                'VTOR':         (0x08, 'VTOR: Vector Table Offset Register'),
                'AIRCR':        (0x0C, 'AIRCR: Application Interrupt and Reset Control Register'),
                'SCR':          (0x10, 'SCR: System Control Register'),
                'CCR':          (0x14, 'CCR: Configuration Control Register'),
                'SHPR1_PRI4':   (0x18, 'Priority of system handler 4, MemManage'),
                'SHPR1_PRI5':   (0x19, 'Priority of system handler 5, BusFault'),
                'SHPR1_PRI7':   (0x1A, 'Priority of system handler 6, UsageFault'),
                'SHPR2_PRI11':  (0x1F, 'Priority of system handler 11, SVCall'),
                'SHPR3_PRI14':  (0x22, 'Priority of system handler 14, PendSV'),
                'SHPR3_PRI15':  (0x23, 'Priority of system handler 15, SysTick exception'),
                'SHCSR':        (0x24, 'SHCSR: System Handler Control and State Register'),
                'DFSR':         (0x30, 'DFSR: Debug Fault Status Register'),
                'CFSR':         (0x28, 'CFSR: Configurable Fault Status Registers'),
                'HFSR':         (0x2C, 'HFSR: Hard Fault Status Register'),
                'MMFAR':        (0x34, 'MMFAR: Memory Manage Fault Address Register'),
                'BFAR':         (0x38, 'BFAR: Bus Fault Address Register'),
                'AFSR':         (0x3C, 'AFSR: Auxiliary Fault Status Register'),
                'ID_PFR0':      (0x40, 'ID_PFR0: Processor Feature Register 0'),
                'ID_PFR1':      (0x44, 'ID_PFR1: Processor Feature Register 1'),
                'ID_DFR0':      (0x48, 'ID_DFR0: Debug Features Register 0'),
                'ID_AFR0':      (0x4C, 'ID_AFR0: Auxiliary Features Register 0'),
                'ID_MMFR0':     (0x50, 'ID_MMFR0: Memory Model Feature Register 0'),
                'ID_MMFR1':     (0x54, 'ID_MMFR1: Memory Model Feature Register 1'),
                'ID_MMFR2':     (0x58, 'ID_MMFR2: Memory Model Feature Register 2'),
                'ID_MMFR3':     (0x5C, 'ID_MMFR1: Memory Model Feature Register 3'),
                'ID_ISAR0':     (0x60, 'ID_ISAR0: Instruction Set Attributes Register 0'),
                'ID_ISAR1':     (0x64, 'ID_ISAR1: Instruction Set Attributes Register 1'),
                'ID_ISAR2':     (0x68, 'ID_ISAR2: Instruction Set Attributes Register 2'),
                'ID_ISAR3':     (0x6C, 'ID_ISAR3: Instruction Set Attributes Register 3'),
                'ID_ISAR4':     (0x70, 'ID_ISAR4: Instruction Set Attributes Register 4'),
                'CPACR':        (0x88, 'CPACR: Coprocessor Access Control Register'),
                'FPCCR':        (0x234, 'FPCCR: Floating-Point Context Control Register'),
                'FPCAR':        (0x238, 'FPCCR: Floating-Point Context Address Register'),
                'FPDSCR':       (0x23C, 'FPDSCR: Floating-Point Default Status Control Register'),
                'MVFR0':        (0x240, 'MVFR0: Media and Floating-Point Feature Register 0'),
                'MVFR1':        (0x244, 'MVFR1: Media and Floating-Point Feature Register 1'),
        }

#-------------------------------------------------------------------
#
# MPU:
#
REGS_MPU    = { 'TYPE': 0x00,   'CTRL': 0x04,   'RNR':  0x08,   'RBAR': 0x0C,
                'RASR': 0x10,
        }

#-------------------------------------------------------------------
#
# STIR:
#
REGS_STIR   = { 'STIR':         (0x0000, 'Software Trigger Interrupt Register'),
        }
#-------------------------------------------------------------------

REGS_DBGMCU = { 'IDCODE':   (0x00, 'MCU ID code. This ID identifies the ST MCU partnumber and the die revision'),
                'CR':       0x04 }

#-------------------------------------------------------------------

REGS_MPU    = { 'TYPE':     0x00,   'CTRL':     0x04,   'RNR':      0x08,   'RBAR':     0x0C,
                'RASR':     0x10 }

REGS_RCC    = { 'CR':       0x00,   'CFGR':     0x04,   'CIR':      0x08,   'APB2RSTR': 0x0C,
                'APB1RSTR': 0x10,   'AHBENR':   0x14,   'APB2ENR':  0x18,   'APB1ENR':  0x1C,
                'BDCR':     0x20,   'CSR':      0x24,   'AHBSTR':   0x28,   'CFGR2':    0x2C }

REGS_ADC    = { 'SR':       0x00,   'CR1':      0x04,   'CR2':      0x08,   'SMPR1':    0x0C,
                'SMPR2':    0x10,   'JOFR1':    0x14,   'JOFR2':    0x18,   'JOFR3':    0x1C,
                'JOFR4':    0x20,   'HTR':      0x24,   'LTR':      0x28,   'SQR1':     0x2C,
                'SQR2':     0x30,   'SQR3':     0x34,   'JSQR':     0x38,   'JDR1':     0x3C,
                'JDR2':     0x40,   'JDR3':     0x44,   'JDR4':     0x48,   'DR':       0x4C }

REGS_DAC    = { 'CR':       0x00,   'SWTRIGR':  0x04,   'DHR12R1':  0x08,   'DHR12L1':  0x0C,
                'DHR8R1':   0x10,   'DHR12R2':  0x14,   'DHR12L2':  0x18,   'DHR8R2':   0x1C,
                'DHR12RD':  0x20,   'DHR12LD':  0x24,   'DHR8RD':   0x28,   'DOR1':     0x2C,
                'DOR2':     0x30 }

REGS_DMA    = { 'ISR':      0x00,   'IFCR':     0x04,   'CCR1':     0x08,   'CNDTR1':   0x0C,
                'CPAR1':    0x10,   'CMAR1':    0x14,                       'CCR2':     0x1C,
                'CNDTR2':   0x20,   'CPAR2':    0x24,   'CMAR2':    0x28,
                'CCR3':     0x30,   'CNDTR3':   0x34,   'CPAR3':    0x38,   'CMAR3':    0x3C,
                                    'CCR4':     0x44,   'CNDTR4':   0x48,   'CPAR4':    0x4C,
                'CMAR4':    0x50,                       'CCR5':     0x58,   'CNDTR5':   0x5C,
                'CPAR6':    0x60,   'CMAR6':    0x64,                       'CCR6':     0x6C,
                'CNDTR6':   0x70,   'CPAR6':    0x74,   'CMAR6':    0x78,
                'CCR7':     0x80,   'CNDTR7':   0x84,   'CPAR7':    0x88,   'CMAR7':    0x8C }

REGS_TIM    = { 'CR1':      0x00,   'CR2':      0x04,   'SMCR':     0x08,   'DIER':     0x0C,
                'SR':       0x10,   'EGR':      0x14,   'CCMR1':    0x18,   'CCMR2':    0x1C,
                'CCER':     0x20,   'CNT':      0x24,   'PSC':      0x28,   'ARR':      0x2C,
                'RCR':      0x30,   'CCR1':     0x34,   'CCR2':     0x38,   'CCR3':     0x3C,
                'CCR4':     0x40,   'BDTR':     0x44,   'DCR':      0x48,   'DMAR':     0x4C }

REGS_RTC    = { 'CRH':      0x00,   'CRL':      0x04,   'PRLH':     0x08,   'PRLL':     0x0C,
                'DIVH':     0x10,   'DIVL':     0x14,   'CNTH':     0x18,   'CNTL':     0x1C,
                'ALRH':     0x20,   'ALRL':     0x24 }

REGS_FSMC   = { 'BCR1':     0x00,   'BTR1':     0x04,   'BCR2':     0x08,   'BTR2':     0x0C,
                'BCR3':     0x10,   'BTR3':     0x14,   'BCR4':     0x18,   'BTR4':     0x1C,
                                    'BWTR1':   0x104,                       'BWTR2':   0x10C,
                                    'BWTR3':   0x114,                       'BWTR4':   0x11C,
                'PCR2': 0xA0000060, 'SR2':  0xA0000064, 'PMEM2':0xA0000068, 'PATT2':0xA000006C,
                                    'ECCR2':0xA0000074,
                'PCR3': 0xA0000080, 'SR3':  0xA0000084, 'PMEM3':0xA0000088, 'PATT3':0xA000008C,
                                    'ECCR3':0xA0000094,
                'PCR4': 0xA00000A0, 'SR4':  0xA00000A4, 'PMEM4':0xA00000A8, 'PATT4':0xA00000AC,
                'PIO4': 0xA00000B0 }

REGS_SDIO   = { 'POWER':    0x00,   'CLKCR':    0x04,   'ARG':      0x08,   'CMD':      0x0C,
                'RESPCMD':  0x10,   'RESP1':    0x14,   'RESP2':    0x18,   'RESP3':    0x1C,
                'RESP4':    0x20,   'DTIMER':   0x24,   'DLEN':     0x28,   'DCTRL':    0x2C,
                'DCOUNT':   0x30,   'STA':      0x34,   'ICR':      0x38,   'MASK':     0x3C,
                                                        'FIFOCNT':  0x48,
                'FIFO':     0x80 }

REGS_USB    = { 'EP0R':     0x00,   'EP1R':     0x04,   'EP2R':     0x08,   'EP3R':     0x0C,
                'EP4R':     0x10,   'EP5R':     0x14,   'EP6R':     0x18,   'EP7R':     0x1C,
                'CNTR':     0x40,   'ISTR':     0x44,   'FNR':      0x48,   'DADDR':    0x4C,
                'BTABLE':   0x50 }

REGS_USB_OTG_FS = {
                #
                # Global CSR map
                #
                'GOTGCTL':  0x00,   'GOTGINT':  0x04,   'GAHBCFG':  0x08,   'GUSBCFG':  0x0C,
                'GRSTCTL':  0x10,   'GINTSTS':  0x14,   'GINTMSK':  0x18,   'GRXSTSR':  0x1C,
                'GRXSTSP':  0x20,   'GRXFSIZ':  0x24,   'HNPTXFSIZ':0x28,   'HNPTXSTS': 0x2C,
                                                        'GCCFG':    0x38,   'CID':      0x3c,
                'HPTXFSIZ': 0x100,
                'OTG_FS_DIEPTXF1': 0x104, # (!)
                'OTG_FS_DIEPTXF2': 0x108, # (!)
                'OTG_FS_DIEPTXF3': 0x10C, # (!)
                #
                # Host-mode CSR map
                #
                'HCFG':     0x400,   'HFIR':    0x404,   'HFNUM':    0x408,
                'HPTXSTS':  0x410,   'HAINT':   0x414,   'HAINTMASK':0x418,
                'HPRT':     0x440,
                #
                # Device-mode CSR map
                #
                'DCFG':     0x800,  'DCTL':    0x804,   'DSTS':    0x808,
                'DIEPMSK':  0x810,  'DOEPMSK': 0x814,   'DAINT':   0x818,   'DAINTMSK':0x81C,
                                                        'DVBUSDIS':0x828, 'DVBUSPULSE':0x82C,
                                    'DIEPEMPMSK':0x834,
                'DIEPCTL0': 0x900,                      'DIEPINT0':0x908,
                'DIEPTSIZ0':0x910,                      'DTXFSTS0':0x918,
                'DIEPCTL1': 0x920,                      'DIEPINT1':0x928,
                'DIEPTSIZ1':0x930,                      'DTXFSTS1':0x938,
                'DIEPCTL2': 0x940,                      'DIEPINT2':0x948,
                'DIEPTSIZ2':0x950,                      'DTXFSTS1':0x958,
                'DIEPCTL3': 0x960,                      'DIEPINT3':0x968,
                'DIEPTSIZ3':0x970,                      'DTXFSTS1':0x978,

                'DOEPCTL0': 0xB00,                      'DOEPINT0':0xB08,
                'DOEPTSIZ0':0xB10,
                'DOEPCTL1': 0xB20,
                'DOEPTSIZ1':0xB30,
                'DOEPCTL2': 0xB40,
                'DOEPTSIZ2':0xB50,
                'DOEPCTL3': 0xB60,
                'DOEPTSIZ3':0xB70,
                'PCGCCTL':  0xE00 }
                #
                # ?!?!?!?!
                #
                # 'DIEPCTLx':0x920, 0x940 ... 0xAE0
                # 'DIEPTSIZx':0x930, 0x950 ... 0xAF0
                # DOEPCTLx':0xB20, 0xB40 ... 0xCC0, 0xCE0, 0xCFD
                #
for n in range(0,7 + 1):
    REGS_USB_OTG_FS[  'HCCHAR{}'.format(n)] = 0x500 + (0x20 * n)
    REGS_USB_OTG_FS[   'HCINT{}'.format(n)] = 0x508 + (0x20 * n)
    REGS_USB_OTG_FS['HCINTMSK{}'.format(n)] = 0x50C + (0x20 * n)
    REGS_USB_OTG_FS[  'HCTSIZ{}'.format(n)] = 0x510 + (0x20 * n)

REGS_ETH    = { 'MACCR':    0x00,   'MACFFR':   0x04,   'MACHTHR':  0x08,   'MACHTLR':  0x0C,
                'MACMIIAR': 0x10,   'MACMIIDR': 0x14,   'MACFCR':   0x18,   'MACVLANTR':0x1C,
                                                        'MACRWUFFR':0x28,   'MACPMTCSR':0x2C,
                                                        'MACSR':    0x38,   'MACIMR':   0x3C,
                'MACA0HR':  0x40,   'MACA0LR':  0x44,   'MACA1HR':  0x48,   'MACA1LR':  0x4C,
                'MACA2HR':  0x50,   'MACA2LR':  0x54,   'MACA3HR':  0x58,   'MACA3LR':  0x5C,
                'MMCCR':   0x100,   'MMCRIR':  0x104,   'MMCTIR':  0x108,   'MMCRIMR': 0x10C,
                'MMCTIMR': 0x110,
                                                                            'MMCTGFSCCR':0x14C,
                'MMCTGFMSCCR':0x150,
                                                        'MMCTGFCR':0x168,
                                    'MMCRFCECR':0x194,  'MMCRFAECR':0x198,
                                    'MMCRGUFCR':0x1C4,
                'PTPTSCR': 0x700,   'PTPSSIR': 0x704,   'PTPTSHR': 0x708,   'PTPTSLR': 0x70C,
                'PTPTSHUR':0x710,   'PTPTSLUR':0x714,   'PTPTSAR': 0x718,   'PTPTTHR': 0x71C,
                'PTPTTLR': 0x720,
                'DMABMR': 0x1000,   'DMATPDR': 0x1004,  'DMARPDR':0x1008,   'DMARDLAR':0x100C,
                'DMATDLAR':0x1010,  'DMASR':   0x1014,  'DMAOMR': 0x1018,   'DMAIER': 0x102C,
                'DMAMFBOCR':0x1020,
                                                        'DMACHTDR':0x1048,  'DMACHRDR':0x104C,
                'DMACHTBAR':0x1050, 'DMACHRBAR':0x1054 }


REGS_CAN    = { 'MCR':      0x00,   'MSR':      0x04,   'TSR':      0x08,   'RF0R':     0x0C,
                'RF1R':     0x10,   'IER':      0x14,   'ESR':      0x18,   'BTR':      0x1C,
                'TI0R':    0x180,   'TDT0R':   0x184,   'TDL0R':   0x188,   'TDH0R':   0x18C,
                'TI1R':    0x190,   'TDT1R':   0x194,   'TDL1R':   0x198,   'TDH1R':   0x19C,
                'TI2R':    0x1A0,   'TDT2R':   0x1A4,   'TDL2R':   0x1A8,   'TDH2R':   0x1AC,
                'RI0R':    0x1B0,   'RDT0R':   0x1B4,   'RDL0R':   0x1B8,   'RDH0R':   0x1BC,
                'RI1R':    0x1C0,   'RDT1R':   0x1C4,   'RDL1R':   0x1C8,   'RDH1R':   0x1CC,
                'FMR':     0x200,   'FM1R':    0x204,                       'FS1R':    0x20C,
                                    'FFA1R':   0x214,                       'FA1R':    0x21C,
                'F0R1':    0x240,   'F0R2':    0x244,   'F1R1':    0x248,   'F1R2':    0x24C,
                                                        'F27R1':   0x318,   'F27R2':   0x31C }

REGS_SPI    = { 'CR1':      0x00,   'CR2':      0x04,   'SR':       0x08,   'DR':       0x0C,
                'CRCPR':    0x10,   'RXCRCR':   0x14,   'TXCRCR':   0x18,   'I2SCFGR':  0x1C,
                'I2SPR':    0x20 }

REGS_I2C    = { 'CR1':      0x00,   'CR2':      0x04,   'OAR1':     0x08,   'OAR2':     0x0C,
                'DR':       0x10,   'SR1':      0x14,   'SR2':      0x18,   'CCR':      0x1C,
                'TRISE':    0x20 }

REGS_USART  = { 'SR':       0x00,   'DR':       0x04,   'BPR':      0x08,   'CR1':      0x0C,
                'CR2':      0x10,   'CR3':      0x14,   'GTPR':     0x18 }

REGS_AFIO   = { 'EVCR':     0x00,   'MAPR':     0x04,   'EXTICR1':  0x08,   'EXTICR2':  0x0C,
                'EXTICR3':  0x10,   'EXTICR4':  0x14,                       'MAPR2':    0x1C }

REGS_GPIO   = { 'CRL':      0x00,   'CRH':      0x04,   'IDR':      0x08,   'ODR':      0x0C,
                'BSRR':     0x10,   'BRR':      0x14,   'LCKR':     0x18 }

REGS_EXTI   = { 'IMR':      0x00,   'EMR':      0x04,   'RTSR':     0x08,   'FTSR':     0x0C,
                'SWIER':    0x10,   'PR':       0x14 }

REGS_IWDG   = { 'KR':       0x00,   'PR':       0x04,   'RLR':      0x08,   'SR':       0x0C }

REGS_WWDG   = { 'CR':       0x00,   'CFR':      0x04,   'SR':       0x08 }

REGS_CRC    = { 'DR':       0x00,   'IDR':      0x04,   'CR':       0x08 }

REGS_PWR    = { 'CR':       0x00,   'CSR':      0x04 }

REGS_BKP    = {                                                             'RTCCR':    0x2C,
                'CR':       0x30,   'CSR':      0x34 }
for n in range(1, 42 + 1):
    REGS_BKP['DR{}'.format(n)] = (n * 4) if (n < 11) else ((n-11)*4 + 0x40)

REGS_DESIG  = { 'FLASH_SIZE':   0x7e0,
                'UNIQUE_ID0':   0x7e8,
                'UNIQUE_ID1':   0x7ec,
                'UNIQUE_ID2':   0x7f0,
            }

#-------------------------------------------------------------------

VALS_RCC_CR = {
    'PLLRD':    (1 << 25),
    'PLLON':    (1 << 24),
    'CSSON':    (1 << 19),
    'HSEBYP':   (1 << 18),
    'HSERDY':   (1 << 17),
    'HSEON':    (1 << 16),
    'HSICAL_SHIFT':     8,
    'HSICAL':   (0xFF << 8), # 8 == RCC_RC_HSICAL_SHIFT
    'HSITRIM_SHIFT':    3,
    'HSITRIM':  (0x1F << 3), # 3 == RCC_RC_HSITRIM_SHIFT
    'HSIRDY':   (1 << 1),
    'HSION':    (1 << 0),
}

VALS_RCC_CFGR = {
    'PLLNODIV': (1 << 31),
    'MCOPRE_SHIFT':     28,
}

VALS_RCC_AHBENR = {
    'TSCEN':    (1 << 24),
    'TSCEN':    (1 << 24)
}


#dump(REGS_BKP)

#-------------------------------------------------------------------
#
# IDA helpers
#
def idaSetOpAddrName(ea, n, Name):
    offs = idc.get_operand_value(ea, n)
    addr = idc.get_wide_dword(offs) & (~1)
    idc.set_name(addr, Name)
    idc.op_plain_offset(offs, 0, 0)
    idc.op_plain_offset(ea, n, 0)

#-------------------------------------------------------------------

def CreateEnum(Regs, BaseAddr, EnumName):

    idc.del_enum(idc.get_enum(EnumName))

    EnumId = idc.add_enum(0, EnumName, idaapi.hex_flag())

    for Reg, Descr in Regs.items():
        Comment = None
        # if isinstance(Descr, (int, long)):
        if isinstance(Descr, int):
            Offset = Descr
        else:
            Offset = Descr[0]
            Comment = Descr[1]

        EnumMemberName = EnumName + '_' + Reg
        idc.add_enum_member(EnumId, EnumMemberName, BaseAddr + Offset, -1)
        if Comment:
            ConstId = idc.get_enum_member_by_name(EnumMemberName)
            idc.set_enum_member_cmt(ConstId, Comment, True)

    #MaxBit = max(Regs.iteritems(), key=operator.itemgetter(1))[1]
    #MaskBit = RoundUpPow2(MaxBit) - 1
    #idc.set_enum_bf(id, 1)


#-------------------------------------------------------------------

def CreateEnumByName(RegsName, BaseAddr, Name=None):

    if not Name:
        Name = RegsName

    Regs = globals()['REGS_' + RegsName]

    EnumName = "REG_" + Name
    CreateEnum(Regs, BaseAddr, EnumName)

#-------------------------------------------------------------------

def CreateEnums():

    Enums = {
        'ITR':      ITR_BASE,
        'SYS_TICK': SYS_TICK_BASE,
        'NVIC':     NVIC_BASE,
        'SCB':      SCB_BASE,
        'MPU':      MPU_BASE,
        'STIR':     STIR_BASE,
        'DBGMCU':   DBGMCU_BASE,
        'DESIG':    INFO_BASE,

        'RCC':      RCC_BASE,
        'RTC':      RTC_BASE,
        'PWR':      POWER_CONTROL_BASE,
        'BKP':      BACKUP_REGS_BASE,
        'CRC':      CRC_BASE,
        'WWDG':     WWDG_BASE,
        'IWDG':     IWDG_BASE,
        'DAC':      DAC_BASE,
        'AFIO':     AFIO_BASE,
        'SDIO':     SDIO_BASE,
        'EXTI':     EXTI_BASE,
        'DESIG':    INFO_BASE,

        'TIM':    [ (TIM1_BASE, 'TIM1'), (TIM2_BASE, 'TIM2'), (TIM3_BASE, 'TIM3'), (TIM4_BASE, 'TIM4'),
                    (TIM5_BASE, 'TIM5'), (TIM6_BASE, 'TIM6'), (TIM7_BASE, 'TIM7'), (TIM8_BASE, 'TIM8'),
                    (TIM9_BASE, 'TIM9'), (TIM10_BASE, 'TIM10'), (TIM11_BASE, 'TIM11'), (TIM12_BASE, 'TIM12'),
                    (TIM13_BASE, 'TIM13'), (TIM14_BASE, 'TIM14'), (TIM15_BASE, 'TIM15'), (TIM16_BASE, 'TIM16'),
                    (TIM17_BASE, 'TIM17') ],

        'GPIO':   [ (GPIO_PORT_A_BASE, 'GPIO_A'), (GPIO_PORT_B_BASE, 'GPIO_B'),
                    (GPIO_PORT_C_BASE, 'GPIO_C'), (GPIO_PORT_D_BASE, 'GPIO_D'),
                    (GPIO_PORT_E_BASE, 'GPIO_E'), (GPIO_PORT_F_BASE, 'GPIO_F'),
                    (GPIO_PORT_G_BASE, 'GPIO_G') ],

        'ADC':    [ (ADC1_BASE, 'ADC1'), (ADC2_BASE, 'ADC2'), (ADC3_BASE, 'ADC3') ],
        'SPI':    [ (SPI1_BASE, 'SPI1'), (SPI2_BASE, 'SPI2'), (SPI3_BASE, 'SPI3') ],
        'I2C':    [ (I2C1_BASE, 'I2C1'), (I2C2_BASE, 'I2C2') ],
        'DMA':    [ (DMA1_BASE, 'DMA1'), (DMA2_BASE, 'DMA2') ],

        'USART':  [ (USART1_BASE, 'USART1'), (USART2_BASE, 'USART2'), (USART3_BASE, 'USART3'), (UART4_BASE, 'UART4'), (UART5_BASE, 'UART5') ],
        'CAN':    [ (BX_CAN1_BASE, 'CAN1'), (BX_CAN2_BASE, 'CAN2') ],

#        'ETH':      ETHERNET_BASE,
#        'USB_OTG_FS': USB_OTG_FS_BASE,
# USB_DEV_FS_BASE
# USB_PMA_BASE
# USB_CAN_SRAM_BASE
# FLASH_MEM_INTERFACE_BASE
    }


    for RegsName, Descr in Enums.items():

        print(RegsName)
        print(Descr)
        print(type(Descr))

        # if isinstance(Descr, (int, long)):
        if isinstance(Descr, int):
            CreateEnumByName(RegsName, Descr)
        else:
            for Item in Descr:
                BaseAddr = Item[0]
                Name = Item[1] if len(Item) > 1 else None
                CreateEnumByName(RegsName, BaseAddr, Name)

#-------------------------------------------------------------------

def CreateVecTable(TableSize=None):

    Vectors = [
        ('InitialSP',),                                                                                                 # 0000
        ('Reset',),                                                                                                     # 0004 (-3)
        ('NMI',             'Non maskable interrupt. The RCC Clock Security System (CSS) is linked to the NMI vector'), # 0008 (-2)
        ('HardFault',       'All class of fault'),                                                                      # 000C (-1)
        ('MemManage',       'Memory management'),                                                                       # 0010 (0)
        ('BusFault',        'Pre-fetch fault, memory access fault'),                                                    # 0014 (1)
        ('UsageFault',      'Undefined instruction or illegal state'),                                                  # 0018 (2)
        ('Reserved0',),                                                                                                 # 001C
        ('Reserved1',),                                                                                                 # 0020
        ('Reserved2',),                                                                                                 # 0024
        ('Reserved3',),                                                                                                 # 0028
        ('SVCall',          'System service call via SWI instruction'),                                                 # 002C (3)
        ('DebugMonitor',    'Debug Monitor'),                                                                           # 0030 (4)
        ('Reserved4',),                                                                                                 # 0034
        ('PendSV',          'Pendable request for system service'),                                                     # 0038 (5)
        ('SysTick',         'System tick timer'),                                                                       # 003C (6)
        ('WWDG',            'Window Watchdog interrupt'),                                                               # 0040 (7)
        ('PVD',             'PVD through EXTI Line detection interrupt'),                                               # 0044 (8)
        ('TAMPER',          'Tamper interrupt'),                                                                        # 0048 (9)
        ('RTC',             'RTC global interrupt'),                                                                    # 004C (10)
        ('FLASH',           'Flash global interrupt'),                                                                  # 0050 (11)
        ('RCC',             'RCC global interrupt'),                                                                    # 0054 (12)
        ('EXTI0',           'EXTI Line0 interrupt'),                                                                    # 0058 (13)
        ('EXTI1',           'EXTI Line1 interrupt'),                                                                    # 005C (14)
        ('EXTI2',           'EXTI Line2 interrupt'),                                                                    # 0060 (15)
        ('EXTI3',           'EXTI Line3 interrupt'),                                                                    # 0064 (16)
        ('EXTI4',           'EXTI Line4 interrupt'),                                                                    # 0068 (17)
        ('DMA1_Ch1',        'DMA1 Channel1 global interrupt'),                                                          # 006C (18)
        ('DMA1_Ch2',        'DMA1 Channel2 global interrupt'),                                                          # 0070 (19)
        ('DMA1_Ch3',        'DMA1 Channel3 global interrupt'),                                                          # 0074 (20)
        ('DMA1_Ch4',        'DMA1 Channel4 global interrupt'),                                                          # 0078 (21)
        ('DMA1_Ch5',        'DMA1 Channel5 global interrupt'),                                                          # 007C (22)
        ('DMA1_Ch6',        'DMA1 Channel6 global interrupt'),                                                          # 0080 (23)
        ('DMA1_Ch7',        'DMA1 Channel7 global interrupt'),                                                          # 0084 (24)
        ('ADC1_2',          'ADC1 and ADC2 global interrupt'),                                                          # 0088 (25)
        ('USB_HP_CAN_TX',   'USB high priority or CAN TX interrupts'),                                                  # 008C (26)
        ('USB_LP_CAN_RX0',  'USB low priority or CAN RX0 interrupts'),                                                  # 0090 (27)
        ('CAN_RX1',         'CAN RX1 interrupt'),                                                                       # 0094 (28)
        ('CAN_SCE',         'CAN SCE interrupt'),                                                                       # 0098 (29)
        ('EXTI9_5',         'EXTI Line[9:5] interrupts'),                                                               # 009C (30)
        ('TIM1_BRK',        'TIM1 Break interrupt'),                                                                    # 00A0 (31)
        ('TIM1_UP',         'TIM1 Update interrupt'),                                                                   # 00A4 (32)
        ('TIM1_TRG_COM',    'TIM1 Trigger and Commutation interrupts'),                                                 # 00A8 (33)
        ('TIM1_CC',         'TIM1 Capture Compare interrupt'),                                                          # 00AC (34)
        ('TIM2',            'TIM2 global interrupt'),                                                                   # 00B0 (35)
        ('TIM3',            'TIM3 global interrupt'),                                                                   # 00B4 (36)
        ('TIM4',            'TIM4 global interrupt'),                                                                   # 00B8 (37)
        ('I2C1_EV',         'I2C1 event interrupt'),                                                                    # 00BC (38)
        ('I2C1_ER',         'I2C1 error interrupt'),                                                                    # 00C0 (39)
        ('I2C2_EV',         'I2C2 event interrupt'),                                                                    # 00C4 (40)
        ('I2C2_ER',         'I2C2 error interrupt'),                                                                    # 00C8 (41)
        ('SPI1',            'SPI1 global interrupt'),                                                                   # 00CC (42)
        ('SPI2',            'SPI2 global interrupt'),                                                                   # 00D0 (43)
        ('USART1',          'USART1 global interrupt'),                                                                 # 00D4 (44)
        ('USART2',          'USART2 global interrupt'),                                                                 # 00D8 (45)
        ('USART3',          'USART3 global interrupt'),                                                                 # 00DC (46)
        ('EXTI15_10',       'EXTI Line[15:10] interrupts'),                                                             # 00E0 (47)
        ('RTCAlarm',        'RTC alarm through EXTI line interrupt'),                                                   # 00E4 (48)
        ('USBWakeup',       'USB wakeup from suspend through EXTI line interrupt'),                                     # 00E8 (49)
        ('TIM8_BRK',        'TIM8 Break interrupt'),                                                                    # 00EC (50)
        ('TIM8_UP',         'TIM8 Update interrupt'),                                                                   # 00F0 (51)
        ('TIM8_TRG_COM',    'TIM8 Trigger and Commutation interrupts'),                                                 # 00F4 (52)
        ('TIM8_CC',         'TIM8 Capture Compare interrupt'),                                                          # 00F8 (53)
        ('ADC3',            'ADC3 global interrupt'),                                                                   # 00FC (54)
        ('FSMC',            'FSMC global interrupt'),                                                                   # 0100 (55)
        ('SDIO',            'SDIO global interrupt'),                                                                   # 0104 (56)
        ('TIM5',            'TIM5 global interrupt'),                                                                   # 0108 (57)
        ('SPI3',            'SPI3 global interrupt'),                                                                   # 010C (58)
        ('UART4',           'UART4 global interrupt'),                                                                  # 0110 (59)
        ('UART5',           'UART5 global interrupt'),                                                                  # 0114 (60)
        ('TIM6',            'TIM6 global interrupt'),                                                                   # 0118 (61)
        ('TIM7',            'TIM7 global interrupt'),                                                                   # 011C (62)
        ('DMA2_Ch1',        'DMA2 Channel1 global interrupt'),                                                          # 0120 (63)
        ('DMA2_Ch2',        'DMA2 Channel2 global interrupt'),                                                          # 0124 (64)
        ('DMA2_Ch3',        'DMA2 Channel3 global interrupt'),                                                          # 0128 (65)
        ('DMA2_Ch4_5',      'DMA2 Channel4 and DMA2 Channel4 global interrupts'),                                       # 012C (66)
    ]

    Base = 0x8000000
    Offset = 0
    for Vector in Vectors:

        ea = (Base + Offset)
        Offset += 4
        Name = Vector[0]
        Comment = None if len(Vector) < 2 else Vector[1]
        '''
        if Comment:
            print('{:02X} {} "{}"'.format(Offset, Name, Comment))
        else:
            print('{:02X} {}'.format(Offset, Name))
        '''
        NameVec = 'Vec_' + Name
        NameTrap = 'Trap_' + Name

        #idc.del_items(ea, 0, 4) # Undef before conversion
        #idaapi.do_unknown_range(ea, 4, 0)
        idaapi.del_items(ea, 0, 4)
        idc.create_dword(ea)
        idc.set_name(ea, NameVec)
        if Comment:
            idc.set_cmt(ea, Comment, False)

        TrapAddr = idc.get_wide_dword(ea) & (~1)
        if 0 != TrapAddr:
            Data = idc.get_wide_word(TrapAddr)

            if Data == 0xe7fe:
                Addr = TrapAddr
                if (0x08000000 == (Addr & 0xFFFF0000)): # Shrink addr to 16-bit
                    Addr = (TrapAddr & 0xFFFF)

                NameTrap = 'TrapHang_{:02x}'.format(Addr)
            idaapi.auto_make_code(TrapAddr)
            idc.set_name(TrapAddr, NameTrap)
            idc.op_plain_offset(ea, 0, 0)

            if 'Reset' == Name:
                Data0 = idc.get_wide_dword(TrapAddr)        # 0x478048xx
                Data1 = idc.get_wide_dword(TrapAddr + 4)    # 0x470048xx
                if (0x47804800 == (Data0 & 0xFFFFFF00)) and (0x47004800 == (Data1 & 0xFFFFFF00)):
                    # ldr r0, #SystemInit
                    # blx r0
                    # ldr r0, #Main
                    # bx r0
                    idaSetOpAddrName(TrapAddr,     1, 'SystemInit')
                    idaSetOpAddrName(TrapAddr + 4, 1, 'Main')


        if TableSize and Offset > TableSize:
            break

#-------------------------------------------------------------------

def CreateSegmentSRAM():

    SRAM_BASE = 0x20000000
    SRAM_SIZE = Features.SRamSize
    SRAM_NAME = 'SRAM'

    startEA = SRAM_BASE
    endEA = SRAM_BASE + SRAM_SIZE - 1

    seg = ida_segment.getseg(startEA)
    Name = ida_segment.get_segm_name(seg) if seg else None
    if Name == SRAM_NAME and startEA == seg.start_ea and endEA == seg.end_ea:
        #
        # SRAM already exist
        #
        pass
    else:
        seg = idaapi.segment_t()
        seg.start_ea = startEA
        seg.end_ea = endEA
        seg.bitness = 1 # 32-bit
        idaapi.add_segm_ex(seg, SRAM_NAME, 'CODE', 0)


#-------------------------------------------------------------------

def Main():
    CreateSegmentSRAM()
    CreateVecTable(Features.VecTableSize)
    CreateEnums()

#    TestEnums()

#-------------------------------------------------------------------

Main()
