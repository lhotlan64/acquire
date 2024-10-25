import ctypes

from acquire.dynamic.windows.types import (
    BOOL,
    DWORD,
    HANDLE,
    LPDWORD,
    LPVOID,
    NTSTATUS,
    PHANDLE,
    PLSA_REFERENCED_DOMAIN_LIST,
    PLSA_TRANSLATED_NAME,
    ULONG,
)

advapi32 = ctypes.WinDLL("advapi32.dll")

OpenProcessToken = advapi32.OpenProcessToken
OpenProcessToken.argtypes = [HANDLE, DWORD, PHANDLE]
OpenProcessToken.restype = BOOL

GetTokenInformation = advapi32.GetTokenInformation
GetTokenInformation.argtypes = [HANDLE, ULONG, LPVOID, DWORD, LPDWORD]
GetTokenInformation.restype = BOOL

LsaOpenPolicy = advapi32.LsaOpenPolicy
LsaOpenPolicy.argtypes = [LPVOID, LPVOID, DWORD, HANDLE]
LsaOpenPolicy.restype = NTSTATUS

LsaLookupSids = advapi32.LsaLookupSids
LsaLookupSids.argtypes = [
    HANDLE,
    ULONG,
    LPVOID,
    ctypes.POINTER(PLSA_REFERENCED_DOMAIN_LIST),
    ctypes.POINTER(PLSA_TRANSLATED_NAME),
]
LsaLookupSids.restype = NTSTATUS

LsaFreeMemory = advapi32.LsaFreeMemory
LsaFreeMemory.argtypes = [LPVOID]
LsaFreeMemory.restype = NTSTATUS

LsaClose = advapi32.LsaClose
LsaClose.argtypes = [HANDLE]
LsaClose.restype = NTSTATUS
