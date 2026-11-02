"""Descripcion del equipo donde corre la inferencia.

Va en cada traza porque la misma peticion con la misma semilla no da la misma salida
en CPU que en GPU: dos corridas solo son comparables si salieron del mismo equipo.
"""

from __future__ import annotations

import ctypes
import os
import platform
import subprocess
import sys
from functools import lru_cache


def _sysctl(key: str) -> str:
    try:
        return subprocess.run(
            ["sysctl", "-n", key], capture_output=True, text=True, check=False
        ).stdout.strip()
    except OSError:
        return ""


@lru_cache(maxsize=1)
def hardware_summary() -> str:
    """Procesador, hilos, RAM y sistema operativo, en una linea."""
    cpu = platform.processor() or platform.machine()
    cores = os.cpu_count() or "?"
    ram = ""
    if sys.platform == "win32":
        class _MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = _MemoryStatus()
        status.dwLength = ctypes.sizeof(_MemoryStatus)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            ram = f", {status.ullTotalPhys / 1024**3:.1f} GB RAM"
    elif sys.platform == "darwin":
        # En macOS `platform.processor()` solo dice "arm"; sysctl da el chip y la RAM.
        cpu = _sysctl("machdep.cpu.brand_string") or cpu
        memory = _sysctl("hw.memsize")
        if memory.isdigit():
            ram = f", {int(memory) / 1024**3:.1f} GB RAM"
    return f"{cpu} ({cores} hilos{ram}), {platform.system()} {platform.release()}"
