/*
 * Intel ACPI Component Architecture
 * AML/ASL+ Disassembler version 20200925 (64-bit version)
 * Copyright (c) 2000 - 2020 Intel Corporation
 * 
 * Disassembling to symbolic ASL+ operators
 *
 * Disassembly of iASLaoO4Va.aml, Tue Apr  4 22:02:47 2023
 *
 * Original Table Header:
 *     Signature        "SSDT"
 *     Length           0x0000064E (1614)
 *     Revision         0x02
 *     Checksum         0x23
 *     OEM ID           "T480"
 *     OEM Table ID     "XHC"
 *     OEM Revision     0x00001000 (4096)
 *     Compiler ID      "INTL"
 *     Compiler Version 0x20210105 (539033861)
 */
// Adapted from EETagent and Valnoxy
//
// Native ACPI-setup for the USB2/3-controller on x80-series Thinkpads
//
// This follows the setup of a T480 with Touchscreen, Fingerprint reader and Windows Hello IR camera.
// The assignments may or may not differ on other configurations.
// When in doubt, do USB Mapping and modify to match.
//
// Reference: https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/extensible-host-controler-interface-usb-xhci.pdf
// Also: https://uefi.org/specs/ACPI/6.5/09_ACPI_Defined_Devices_and_Device_Specific_Objects.html#upc-usb-port-capabilities
//
DefinitionBlock ("", "SSDT", 2, "T480", "XHC", 0x00001000)
{
    External (_SB_.PCI0, DeviceObj)
    External (_SB_.PCI0.XHC_, DeviceObj)
    External (_SB_.PCI0.XHC_.RHUB.HS01, DeviceObj)
    External (_SB_.PCI0.XHC_.RHUB.HS02, DeviceObj)
    External (_SB_.PCI0.XHC_.RHUB.HS03, DeviceObj)
    External (_SB_.PCI0.XHC_.RHUB.HS04, DeviceObj)
    External (_SB_.PCI0.XHC_.RHUB.HS05, DeviceObj)
    External (_SB_.PCI0.XHC_.RHUB.HS06, DeviceObj)
    External (_SB_.PCI0.XHC_.RHUB.HS07, DeviceObj)
    External (_SB_.PCI0.XHC_.RHUB.HS08, DeviceObj)
    External (_SB_.PCI0.XHC_.RHUB.SS01, DeviceObj)
    External (_SB_.PCI0.XHC_.RHUB.SS02, DeviceObj)
    External (_SB_.PCI0.XHC_.RHUB.SS03, DeviceObj)
    External (_SB_.PCI0.XHC_.RHUB.SS04, DeviceObj)
    External (_SB_.PCI0.RP09.UPSB.DSB2.XHC2, DeviceObj)
    External (_SB_.PCI0.RP09.UPSB.DSB2.XHC2.MODU, MethodObj)    // 0 Arguments
    
    // SSDT-UTILS
    External (DTGP, MethodObj)    // 5 Arguments
    External (OSDW, MethodObj)    // 0 Arguments

    Scope (\_SB.PCI0.XHC)
    {
        If (OSDW ())
        {
            Name (_GPE, 0x6D)  // _GPE: General Purpose Events
        }

        Method (RTPC, 1, Serialized)
        {
            Debug = "XHC:RTPC"
            Return (Zero)
        }

        Method (MODU, 0, Serialized)
        {
            Debug = "XHC:MODU"
            If (CondRefOf (\_SB.PCI0.RP09.UPSB.DSB2.XHC2.MODU))
            {
                Return (\_SB.PCI0.RP09.UPSB.DSB2.XHC2.MODU ())
            }
            Else
            {
                Return (One)
            }
        }
    }

    // USB 3 Type-A (Bottom Right) (EHCI)
    Scope (\_SB.PCI0.XHC.RHUB.HS01)
    {
        Method (_UPC, 0, Serialized)  // _UPC: USB Port Capabilities
        {
            Return (Package (0x04)
            {
                0xFF, 
                0x03, 
                Zero, 
                Zero
            })
        }
    }

    // USB 3 Type-A (Top Right) (EHCI)
    Scope (\_SB.PCI0.XHC.RHUB.HS02)
    {
        Method (_UPC, 0, Serialized)  // _UPC: USB Port Capabilities
        {
            Return (Package (0x04)
            {
                0xFF, 
                0x03, 
                Zero, 
                Zero
            })
        }
    }

    // USB 3 Type-C/Charging Port (Top Left) (EHCI)
    Scope (\_SB.PCI0.XHC.RHUB.HS03)
    {
        Method (_UPC, 0, Serialized)  // _UPC: USB Port Capabilities
        {
            Return (Package (0x04) {
                0xFF,
                0x09,
                Zero,
                Zero
            })
        }
    }

    // Builtin IR Camera, disabled
    Scope (\_SB.PCI0.XHC.RHUB.HS04)
    {
        Method (_UPC, 0, Serialized)  // _UPC: USB Port Capabilities
        {
            If (OSDW()) {
                Return (Package (0x04) {
                    Zero,
                    Zero,
                    Zero,
                    Zero
                })
            } Else {
                Return (Package (0x04) {
                    0xFF, 
                    0xFF, 
                    Zero, 
                    Zero
                })
            }
        }
    }

    // Builtin Bluetooth
    Scope (\_SB.PCI0.XHC.RHUB.HS05)
    {
        Method (_UPC, 0, Serialized)  // _UPC: USB Port Capabilities
        {
            Return (Package (0x04) {
                0xFF,
                0xFF,
                Zero,
                Zero
            })
        }
    }

    // Builtin Camera
    Scope (\_SB.PCI0.XHC.RHUB.HS06)
    {
        Method (_UPC, 0, Serialized)  // _UPC: USB Port Capabilities
        {
            Return (Package (0x04)
            {
                0xFF, 
                0xFF, 
                Zero, 
                Zero
            })
        }
    }

    // Builtin Fingerprint Reader, disabled
    Scope (\_SB.PCI0.XHC.RHUB.HS07)
    {
        Method (_UPC, 0, Serialized)  // _UPC: USB Port Capabilities
        {
            Return (Package (0x04)
            {
                0xFF, 
                0xFF, 
                Zero, 
                Zero
            })
        }
    }

    // Builtin Touchscreen
    Scope (\_SB.PCI0.XHC.RHUB.HS08)
    {
        Method (_UPC, 0, Serialized)  // _UPC: USB Port Capabilities
        {
            Return (Package (0x04)
            {
                0xFF, 
                0xFF, 
                Zero, 
                Zero
            })
        }
    }

    // USB 3 Type-A (Bottom Right) (XHCI)
    Scope (\_SB.PCI0.XHC.RHUB.SS01)
    {
        Method (_UPC, 0, Serialized)  // _UPC: USB Port Capabilities
        {
            Return (Package (0x04)
            {
                0xFF, 
                0x03,
                Zero, 
                Zero
            })
        }
    }

    // USB 3 Type-A (Top Right) (XHCI)
    Scope (\_SB.PCI0.XHC.RHUB.SS02)
    {
        Method (_UPC, 0, Serialized)  // _UPC: USB Port Capabilities
        {
            Return (Package (0x04)
            {
                0xFF, 
                0x03, 
                Zero, 
                Zero
            })
        }
    }

    // Builtin Card Reader (XHCI)
    Scope (\_SB.PCI0.XHC.RHUB.SS03)
    {
        Method (_UPC, 0, Serialized)  // _UPC: USB Port Capabilities
        {
            
            Return (Package (0x04)
            {
                0xFF, 
                0xFF, 
                Zero, 
                Zero
            })
        }
    }

    // USB 3 Type-C/Charging Port (Top Left) (XHCI)
    Scope (\_SB.PCI0.XHC.RHUB.SS04)
    {
        Method (_UPC, 0, Serialized)  // _UPC: USB Port Capabilities
        {
            Return (Package (0x04)
            {
                0xFF, 
                0x09, 
                Zero, 
                Zero
            })
        }
    }


    Scope (\_SB)
    {
        /*
         * AppleUsbPower compatibility table for Skylake+.
         *
         * Be warned that power supply values can be different
         * for different systems. Depending on the configuration
         * these values must match injected IOKitPersonalities
         * for com.apple.driver.AppleUSBMergeNub. iPad remains
         * being the most reliable device for testing USB port
         * charging support.
         *
         * Try NOT to rename EC0, H_EC, etc. to EC.
         * These devices are incompatible with macOS and may break
         * at any time. AppleACPIEC kext must NOT load.
         * See the disable code below.
         *
         * Reference: https://dortania.github.io/OpenCore-Post-Install/usb/misc/power.html
         */
        Device (\_SB.USBX)
        {
            Name (_ADR, Zero)  // _ADR: Address
            Method (_DSM, 4, NotSerialized)  // _DSM: Device-Specific Method
            {
                Local0 = Package (0x08)
                    {
                        "kUSBSleepPortCurrentLimit", 
                        0x0834, 
                        "kUSBWakePortCurrentLimit", 
                        0x0834, 
                        "kUSBSleepPowerSupply", 
                        0x13EC, 
                        "kUSBWakePowerSupply", 
                        0x13EC
                    }
                DTGP (Arg0, Arg1, Arg2, Arg3, RefOf (Local0))
                Return (Local0)
            }

            Method (_STA, 0, NotSerialized)  // _STA: Status
            {
                If (OSDW ())
                {
                    Return (0x0F)
                }

                Return (Zero)
            }
        }
    }
}

