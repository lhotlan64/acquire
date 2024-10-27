import ctypes
from ctypes.wintypes import FILETIME

from acquire.dynamic.windows.types import BOOL, LPVOID

kernel32 = ctypes.windll.kernel32

FileTimeToSystemTime = kernel32.FileTimeToSystemTime
FileTimeToSystemTime.argtypes = [ctypes.POINTER(FILETIME), LPVOID]
FileTimeToSystemTime.restype = BOOL

SystemTimeToTzSpecificLocalTime = kernel32.SystemTimeToTzSpecificLocalTime
SystemTimeToTzSpecificLocalTime.argtypes = [LPVOID, LPVOID, LPVOID]
SystemTimeToTzSpecificLocalTime.restype = BOOL
