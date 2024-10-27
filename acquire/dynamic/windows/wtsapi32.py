import ctypes

from acquire.dynamic.windows.types import BOOL, DWORD, HANDLE, LPDWORD, LPVOID

wtsapi32 = ctypes.WinDLL("wtsapi32.dll")

WTSEnumerateSessionsW = wtsapi32.WTSEnumerateSessionsW
WTSEnumerateSessionsW.argtypes = [HANDLE, DWORD, DWORD, LPVOID, LPDWORD]
WTSEnumerateSessionsW.restype = BOOL

WTSQuerySessionInformationW = wtsapi32.WTSQuerySessionInformationW
WTSQuerySessionInformationW.argtypes = [HANDLE, DWORD, DWORD, ctypes.POINTER(LPVOID), LPDWORD]
WTSQuerySessionInformationW.restype = BOOL

WTSFreeMemory = wtsapi32.WTSFreeMemory
WTSFreeMemory.argtypes = [LPVOID]
WTSFreeMemory.restype = None

WTS_CURRENT_SERVER_HANDLE = HANDLE(0)
