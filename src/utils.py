import os
import apt
import gi
import socket
import psutil

gi.require_version("GLib", "2.0")
gi.require_version("GUdev", "1.0")
from gi.repository import GLib, Gio, GUdev


cpuinfo_path = "/proc/cpuinfo"
gpu_class = 0x030000
dc_class = 0x038000
sec_gpu_class = 0x030200
pci_dev_path = "/sys/bus/pci/devices"
pci_id_paths = ["/usr/share/misc/pci.ids", "/usr/share/hwdata/pci.ids"]


def int2hex(num):
    """
    Convert an integer to its hexadecimal string representation.

    :param num: The integer to convert.
    :return: A string representing the hexadecimal value of the integer.
    """
    return str(hex(num)[2:]).upper()


def line_split(line):
    """
    Split a line from /proc/cpuinfo on the tab and colon characters and strip whitespace.

    :param line: The line to split.
    :return: The part of the line after the tab and colon, stripped of leading and trailing whitespace.
    """
    return line.split("\t:")[1].strip()


def get_desktop_environment():
    """
    Get the desktop environment of the current user.
    """

    desktop_session = os.environ.get("XDG_CURRENT_DESKTOP")
    desktop_session = "Unknown" if desktop_session is None else desktop_session
    desktop_version = "Unknown"
    cache = apt.Cache()
    if desktop_session == "GNOME":
        gnome = cache["gnome-shell"]
        desktop_version = gnome.installed.version.split("-")[0]
    elif desktop_session == "XFCE":
        xfce = cache["xfce4"]
        desktop_version = xfce.installed.version.split("-")[0]

    return desktop_session, desktop_version


def get_cpu():
    """
    Parse the /proc/cpuinfo file to retrieve CPU information and return an instance of the CPU class.

    :return: An instance of the CPU class populated with information from /proc/cpuinfo.
    """
    with open(cpuinfo_path, "r") as f:
        file_content = f.readlines()
        model = None
        thread_no = 0
        for line in file_content:
            if "model name" in line:
                model = line_split(line)
            if "siblings" in line:
                thread_no += 1

        return model, thread_no


def parse_pci_ids():
    """
    Parse the PCI IDs from the pci.ids files and create a dictionary of devices.

    :return: A dictionary where keys are vendor IDs and values are dictionaries with vendor and device information.
    """
    for p in pci_id_paths:
        if os.path.isfile(p):
            with open(p, "r") as f:
                lines = f.readlines()
            devices = {}
            current_vendor = None

            for line in lines:
                if line.startswith("#") or line.strip() == "":
                    continue

                if not line.startswith("\t"):
                    # This is a vendor entry
                    if current_vendor:
                        devices[current_vendor] = vendor_info
                    vendor_id, vendor_name = line.strip().split(" ", 1)
                    current_vendor = int2hex(int(vendor_id, 16))
                    vendor_info = {"vendor_name": vendor_name.strip(), "devices": []}
                else:
                    # This is a device entry
                    device_id, device_name = line.strip().split(" ", 1)
                    vendor_info["devices"].append(
                        {
                            "device_id": int2hex(int(device_id, 16)),
                            "device_name": device_name.strip(),
                            "vendor_name": vendor_info["vendor_name"],
                        }
                    )
            if current_vendor:
                devices[current_vendor] = vendor_info

            return devices


parsed_pci_ids = parse_pci_ids()


def get_device_name(vendor_id, device_id):
    """
    Retrieve the device name for a given vendor and device ID.

    """
    for dev in parsed_pci_ids[vendor_id]["devices"]:
        if dev["device_id"] == device_id:
            return dev["device_name"]


def get_gpu():
    """
    Get GPU information.
    """
    devices = []
    for root, dirs, files in os.walk(pci_dev_path):
        for pci_dir in dirs:
            dev_content_path = os.path.join(root, pci_dir, "class")
            if os.path.exists(dev_content_path):
                with open(dev_content_path, "r") as f:
                    cont = f.readline().strip()
                    cont = int(cont, 16)
                    if cont == gpu_class or cont == dc_class or cont == sec_gpu_class:
                        is_secondary_gpu = cont == sec_gpu_class
                        vendor_id = None
                        driver = None
                        device_id = cont
                        ven_content_path = os.path.join(root, pci_dir, "vendor")
                        if os.path.exists(ven_content_path):
                            with open(ven_content_path) as f:
                                vendor_id = f.readline().strip()
                                vendor_id = int2hex(int(vendor_id, 16))
                        dev_content_path = os.path.join(root, pci_dir, "device")
                        if os.path.exists(dev_content_path):
                            with open(dev_content_path) as f:
                                device_id = f.readline().strip()
                                device_id = int2hex(int(device_id, 16))
                        drv_content_path = os.path.join(
                            root, pci_dir, "driver", "module"
                        )
                        if os.path.exists(drv_content_path):
                            gpu_drv_p = os.readlink(drv_content_path)
                            driver = os.path.basename(gpu_drv_p)
                        vendor = parsed_pci_ids[vendor_id]["vendor_name"]
                        vendor_short = ""
                        if "INTEL" in vendor.upper():
                            vendor_short = "INTEL"
                        elif "AMD" in vendor.upper():
                            vendor_short = "AMD"
                        elif "NVIDIA" in vendor.upper():
                            vendor_short = "NVIDIA"

                        device = get_device_name(vendor_id, device_id)
                        devices.append(
                            {
                                "vendor": vendor,
                                "vendor_short": vendor_short,
                                "class": cont,
                                "device": device,
                                "driver": driver,
                                "is_secondary_gpu": is_secondary_gpu,
                            }
                        )
    devices.sort(key=lambda devices: devices["class"], reverse=True)
    return devices


def get_os_info():
    """
    Get OS information
    """
    kernel = os.uname().sysname
    release = os.uname().release
    os_fullname = GLib.get_os_info("PRETTY_NAME")
    os_arch = os.uname().machine
    return kernel, release, os_fullname + " " + os_arch


def get_kernel():
    """
    Get the kernel version.
    """
    kernel = os.uname().sysname
    release = os.uname().release
    return kernel, release


def get_ram_size():
    client = GUdev.Client.new(["dmi"])
    device = client.query_by_sysfs_path("/sys/devices/virtual/dmi/id")

    num_ram = device.get_property_as_uint64("MEMORY_ARRAY_NUM_DEVICES")
    ram_total = 0
    for i in range(num_ram):
        ram_size = device.get_property_as_uint64(f"MEMORY_DEVICE_{i}_SIZE")
        ram_total += ram_size

    return ram_total / (1024**3)  # e.g.: 16.0


def get_disk_usage():
    usage = psutil.disk_usage('/')
    total_gb = usage.total / (1024**3)
    used_gb = usage.used / (1024**3)
    free_gb = usage.free / (1024**3)
    percent = usage.percent

    return total_gb, used_gb, free_gb, percent

def get_credentials():
    """
    Get the current user and the hostname
    """
    return os.environ.get("USER"), os.uname().nodename


def get_uptime():
    """
    Get the system uptime in pretty format.
    """
    with open("/proc/uptime", "r") as f:
        uptime_seconds = float(f.readline().split()[0])
        uptime = uptime_seconds
        uptime_str = ""
        if uptime > 86400:
            uptime_str += f"{int(uptime // 86400)} days, "
            uptime %= 86400
        if uptime > 3600:
            uptime_str += f"{int(uptime // 3600)} hours, "
            uptime %= 3600
        if uptime > 60:
            uptime_str += f"{int(uptime // 60)} minutes, "
            uptime %= 60
        uptime_str += f"{int(uptime)} seconds"
        return uptime_str


def get_total_installed_packages():
    """
    Get the total number of installed packages.
    """
    cache = apt.Cache()
    return len([pkg for pkg in cache if pkg.is_installed])


def get_shell():
    """
    Get the current shell name and version
    """
    shell = os.environ.get("SHELL").split("/")[-1]
    if shell:
        return shell
    return "Unknown"


def get_window_manager():
    """
    Get the current window manager depend on the desktop environment
    """
    desktop_env = os.environ.get("XDG_CURRENT_DESKTOP")
    if desktop_env == "GNOME":
        return "Mutter"
    elif desktop_env == "XFCE":
        return "Xfwm4"
    return "Unknown"


def get_wm_theme():
    """
    Get the current window manager theme depends on the window manager
    """
    desktop_env = os.environ.get("XDG_CURRENT_DESKTOP")
    settings = Gio.Settings.new("org.gnome.desktop.interface")
    if desktop_env == "GNOME":
        return settings.get_value("gtk-theme").unpack()
    elif desktop_env == "XFCE":
        return "Xfce"
    return "Unknown"


def local_ip_with_interfaces():
    ip_with_interfaces = {}
    ignore_prefixes = ["lo", "docker", "veth", "br", "virbr"]

    for iface, addrs in psutil.net_if_addrs().items():
        if iface == "lo":
            continue
        local_ip = None
        real_ip = None
        is_real = False

        if not any(iface.startswith(prefix) for prefix in ignore_prefixes):
            is_real = True

        for addr in addrs:
            if addr.family == socket.AF_INET:
                local_ip = addr.address

        if local_ip and is_real:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    real_ip = s.getsockname()[0]

            except OSError:
                real_ip = None

        if local_ip:
            ip_with_interfaces[iface] = {
                "local_ip": local_ip,
                "real_ip": real_ip,
                "is_real": is_real,
            }

    return ip_with_interfaces
