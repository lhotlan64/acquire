import ctypes

from acquire.dynamic.windows.types import (
    BOOL,
    DWORD,
    HANDLE,
    HWND,
    LPARAM,
    LPDWORD,
    LPWSTR,
    WINDOWINFO,
)

user32 = ctypes.WinDLL("user32.dll")

EnumChildWindows = user32.EnumChildWindows
EnumChildWindows.argtypes = [HANDLE, HWND, LPARAM]
EnumChildWindows.restype = BOOL

GetWindowThreadProcessId = user32.GetWindowThreadProcessId
GetWindowThreadProcessId.argtypes = [HWND, LPDWORD]
GetWindowThreadProcessId.restype = DWORD

IsWindowVisible = user32.IsWindowVisible
IsWindowVisible.argtypes = [HWND]
IsWindowVisible.restype = BOOL

GetParent = user32.GetParent
GetParent.argtypes = [HWND]
GetParent.restype = HWND

InternalGetWindowText = user32.GetWindowTextW
InternalGetWindowText.argtypes = [HWND, LPWSTR, ctypes.c_int32]
InternalGetWindowText.restype = ctypes.c_int32

GetWindowInfo = user32.GetWindowInfo
GetWindowInfo.argtypes = [HWND, ctypes.POINTER(WINDOWINFO)]
GetWindowInfo.restype = BOOL
