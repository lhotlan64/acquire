from __future__ import annotations

import ctypes
from ctypes.wintypes import (
    ATOM,
    BOOL,
    DWORD,
    HANDLE,
    LPDWORD,
    LPVOID,
    LPWSTR,
    PHANDLE,
    PULONG,
    RECT,
    UINT,
    ULONG,
    USHORT,
    WCHAR,
    WORD,
)
from enum import IntEnum

PVOID = ctypes.c_void_p
NTSTATUS = ULONG
NULL = None

ULONG_PTR = ctypes.c_size_t
SIZE_T = ctypes.c_size_t

HWND = HANDLE
LPARAM = ULONG_PTR
WPARAM = ULONG_PTR


class ProcessToken(IntEnum):
    TOKEN_QUERY = 0x0008
    TOKEN_ADJUST_PRIVILEGES = 0x0020


class ProcessAccess(IntEnum):
    PROCESS_TERMINATE = 0x0001
    PROCESS_CREATE_THREAD = 0x0002
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_DUP_HANDLE = 0x0040
    PROCESS_CREATE_PROCESS = 0x0080
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_SET_INFORMATION = 0x0200
    PROCESS_QUERY_INFORMATION = 0x0400
    SYNCHRONIZE = 0x00100000
    PROCESS_ALL_ACCESS = 0x1F0FFF


class ErrorCode(IntEnum):
    ERROR_SUCCESS = 0x0
    ERROR_ACCESS_DENIED = 0x5
    ERROR_INVALID_PARAMETER = 0x57
    ERROR_PARTIAL_COPY = 0x12B
    ERROR_NOT_ALL_ASSIGNED = 0x514


class DuplicateHandleFlags(IntEnum):
    DUPLICATE_CLOSE_SOURCE = 0x00000001
    DUPLICATE_SAME_ACCESS = 0x00000002
    DUPLICATE_SAME_ATTRIBUTES = 0x00000004


class SYSTEM_INFORMATION_CLASS(IntEnum):
    SystemHandleInformation = 0x10
    SystemExtendedHandleInformation = 0x40


class OBJECT_INFORMATION_CLASS(IntEnum):
    ObjectBasicInformation = 0
    ObjectNameInformation = 1
    ObjectTypeInformation = 2


class FILE_INFORMATION_CLASS(IntEnum):
    FileNameInformation = 9


class SID_NAME_USE(IntEnum):
    USER = 1
    GROUP = 2
    DOMAIN = 3
    ALIAS = 4
    WELLKNOWNGROUP = 5
    DELETEDACCOUNT = 6
    INVALID = 7
    UNKNOWN = 8
    COMPUTER = 9
    LABEL = 10
    LOGONSESSION = 11


class PROCESSINFOCLASS(IntEnum):
    PROCESSBASICINFORMATION = 0
    PROCESSVMCOUNTERS = 3
    PROCESSTIMES = 4
    PROCESSSESSIONINFORMATION = 24
    PROCESSIMAGEFILENAME = 27
    PROCESSWINDOWINFORMATION = 50


class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ("Object", PVOID),
        ("UniqueProcessId", ULONG_PTR),
        ("HandleValue", ULONG_PTR),
        ("GrantedAccess", ULONG),
        ("CreatorBackTraceIndex", USHORT),
        ("ObjectTypeIndex", USHORT),
        ("HandleAttributes", ULONG),
        ("Reserved", ULONG),
    ]

    @property
    def object(self) -> str:
        return hex(self.Object)

    @property
    def unique_process_id(self) -> str:
        return str(self.UniqueProcessId)

    @property
    def handle_value(self) -> str:
        return str(self.HandleValue)

    @property
    def granted_access(self) -> str:
        return str(self.GrantedAccess)

    @property
    def creator_back_trace_index(self) -> str:
        return str(self.CreatorBackTraceIndex)

    @property
    def object_type_index(self) -> str:
        return str(self.ObjectTypeIndex)

    @property
    def handle_attributes(self) -> str:
        return str(self.HandleAttributes)

    @property
    def reserved(self) -> str:
        return str(self.Reserved)


class SYSTEM_HANDLE_INFORMATION_EX(ctypes.Structure):
    _fields_ = [
        ("NumberOfHandles", ULONG_PTR),
        ("Reserved", ULONG_PTR),
        ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 1),
    ]


def FileNameInformationFactory(file_name_size: int = 1):
    class FILE_NAME_INFORMATION(ctypes.Structure):
        _fields_ = [("FileNameLength", ULONG), ("FileName", WCHAR * file_name_size)]

    return FILE_NAME_INFORMATION()


class IO_STATUS_BLOCK_DUMMYUNIONNAME(ctypes.Union):
    _fields_ = [("Status", NTSTATUS), ("Pointer", ULONG_PTR)]


class IO_STATUS_BLOCK(ctypes.Structure):
    _fields_ = [("DUMMYUNIONNAME", IO_STATUS_BLOCK_DUMMYUNIONNAME), ("Information", ctypes.c_size_t)]


class LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", DWORD),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", 1 * LUID_AND_ATTRIBUTES),
    ]


class Handle:
    """Handle object"""

    def __init__(self, handle: SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, handle_type: str, handle_name: str) -> None:
        self.name = handle_name
        self.handle_type = handle_type

        self.object = handle.object
        self.unique_process_id = handle.unique_process_id
        self.handle_value = handle.handle_value
        self.granted_access = handle.granted_access
        self.creator_back_trace_index = handle.creator_back_trace_index
        self.object_type_index = handle.object_type_index
        self.handle_attributes = handle.handle_attributes
        self.reserved = handle.reserved
        self._handle = handle

    @property
    def dictionary(self):
        return {key: value for key, value in self.__dict__.items() if not key.startswith("_")}


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", LPWSTR),
    ]

    def __str__(self) -> str:
        return self.Buffer

    @classmethod
    def from_str(cls, value: str) -> UNICODE_STRING:
        """Initializes a UNICODE_STRING structure."""
        destination = cls()
        value_buffer = ctypes.create_unicode_buffer(value)

        ctypes.memset(ctypes.addressof(destination), 0, ctypes.sizeof(destination))
        destination.Buffer = ctypes.cast(value_buffer, LPWSTR)
        destination.Length = ctypes.sizeof(value_buffer) - 2  # Excluding terminating NULL character
        destination.MaximumLength = destination.Length

        return destination


class PUBLIC_OBJECT_TYPE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Name", UNICODE_STRING),
        ("Reserved", ULONG * 22),
    ]

    @property
    def name(self) -> str:
        return str(self.Name)


PUNICODE_STRING = ctypes.POINTER(UNICODE_STRING)


class OBJECT_DIRECTORY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Name", UNICODE_STRING),
        ("TypeName", UNICODE_STRING),
    ]

    @property
    def name(self) -> str:
        return str(self.Name)

    @property
    def type_name(self) -> str:
        return str(self.TypeName)


class WTS_SESSION_INFOW(ctypes.Structure):
    _fields_ = [
        ("SessionId", DWORD),
        ("Padding", DWORD),
        ("pWinStationName", LPWSTR),
        ("State", DWORD),
    ]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", LPVOID),
        ("Attributes", DWORD),
    ]


class TOKEN_USER(ctypes.Structure):
    _fields_ = [
        ("User", SID_AND_ATTRIBUTES),
    ]


class LSA_OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Length", ULONG),
        ("Padding", ULONG),
        ("RootDirectory", HANDLE),
        ("ObjectName", ctypes.POINTER(UNICODE_STRING)),
        ("Attributes", ULONG),
        ("Padding2", ULONG),
        ("SecurityDescriptor", LPVOID),
        ("SecurityQualityOfService", LPVOID),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", NTSTATUS),
        ("PebBaseAddress", LPVOID),
        ("AffinityMask", ULONG_PTR),
        ("BasePriority", ULONG),
        ("UniqueProcessId", HANDLE),
        ("InheritedFromUniqueProcessId", HANDLE),
    ]


class PROCESS_EXTENDED_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Size", SIZE_T),
        ("BasicInfo", PROCESS_BASIC_INFORMATION),
        ("Flags", ULONG),  # of interest is IsFrozen (bit 4)
    ]


class PROCESS_SESSION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("SessionId", ULONG),
    ]


class LSA_TRANSLATED_NAME(ctypes.Structure):
    _fields_ = [
        ("Use", ULONG),
        ("Name", UNICODE_STRING),
        ("DomainIndex", ULONG),
    ]


PLSA_TRANSLATED_NAME = ctypes.POINTER(LSA_TRANSLATED_NAME)


class LSA_TRUST_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Name", UNICODE_STRING),
        ("Sid", LPVOID),
    ]


class LSA_REFERENCED_DOMAIN_LIST(ctypes.Structure):
    _fields_ = [
        ("Entries", ULONG),
        ("Domains", ctypes.POINTER(LSA_TRUST_INFORMATION) * 1),
    ]


PLSA_REFERENCED_DOMAIN_LIST = ctypes.POINTER(LSA_REFERENCED_DOMAIN_LIST)


class LARGE_INTEGER(ctypes.Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", DWORD),
    ]


class CLIENT_ID(ctypes.Structure):
    _fields_ = [
        ("UniqueProcess", HANDLE),
        ("UniqueThread", HANDLE),
    ]


class SYSTEM_THREAD_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("KernelTime", LARGE_INTEGER),
        ("UserTime", LARGE_INTEGER),
        ("CreateTime", LARGE_INTEGER),
        ("WaitTime", ULONG),
        ("StartAddress", LPVOID),
        ("ClientId", CLIENT_ID),
        ("Priority", ULONG),
        ("BasePriority", ULONG),
        ("ContextSwitches", ULONG),
        ("ThreadState", ULONG),
        ("WaitReason", ULONG),
    ]


class SYSTEM_PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset", ULONG),
        ("NumberOfThreads", ULONG),
        ("WorkingSetPrivateSize", LARGE_INTEGER),
        ("HardFaultCount", ULONG),
        ("NumberOfThreadsHighWatermark", ULONG),
        ("CycleTime", ULONG),
        ("Padding", ULONG),  # add padding to fix structure alignment
        ("CreateTime", LARGE_INTEGER),
        ("UserTime", LARGE_INTEGER),
        ("KernelTime", LARGE_INTEGER),
        ("ImageName", UNICODE_STRING),
        ("BasePriority", ULONG),
        ("UniqueProcessId", HANDLE),
        ("InheritedFromUniqueProcessId", HANDLE),
        ("HandleCount", ULONG),
        ("SessionId", ULONG),
        ("UniqueProcessKey", ULONG_PTR),
        ("PeakVirtualSize", SIZE_T),
        ("VirtualSize", SIZE_T),
        ("PageFaultCount", ULONG),
        ("PeakWorkingSetSize", SIZE_T),
        ("WorkingSetSize", SIZE_T),
        ("QuotaPeakPagedPoolUsage", SIZE_T),
        ("QuotaPagedPoolUsage", SIZE_T),
        ("QuotaPeakNonPagedPoolUsage", SIZE_T),
        ("QuotaNonPagedPoolUsage", SIZE_T),
        ("PagefileUsage", SIZE_T),
        ("PeakPagefileUsage", SIZE_T),
        ("PrivatePageCount", SIZE_T),
        ("ReadOperationCount", LARGE_INTEGER),
        ("WriteOperationCount", LARGE_INTEGER),
        ("OtherOperationCount", LARGE_INTEGER),
        ("ReadTransferCount", LARGE_INTEGER),
        ("WriteTransferCount", LARGE_INTEGER),
        ("OtherTransferCount", LARGE_INTEGER),
        ("Threads", SYSTEM_THREAD_INFORMATION * 1),
    ]


class WINDOWINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", DWORD),
        ("rcWindow", RECT),
        ("rcClient", RECT),
        ("dwStyle", DWORD),
        ("dwExStyle", DWORD),
        ("dwWindowStatus", DWORD),
        ("cxWindowBorders", UINT),
        ("cyWindowBorders", UINT),
        ("atomWindowType", ATOM),
        ("wCreatorVersion", WORD),
    ]


__all__ = [
    "BOOL",
    "CLIENT_ID",
    "DuplicateHandleFlags",
    "DWORD",
    "ErrorCode",
    "FILE_INFORMATION_CLASS",
    "Handle",
    "HANDLE",
    "IO_STATUS_BLOCK",
    "IO_STATUS_BLOCK_DUMMYUNIONNAME",
    "LARGE_INTEGER",
    "LPDWORD",
    "LPVOID",
    "LPWSTR",
    "LSA_OBJECT_ATTRIBUTES",
    "LSA_REFERENCED_DOMAIN_LIST" "LSA_TRANSLATED_NAME",
    "LSA_TRUST_INFORMATION",
    "LUID",
    "LUID_AND_ATTRIBUTES",
    "NTSTATUS",
    "NULL",
    "OBJECT_DIRECTORY_INFORMATION",
    "OBJECT_INFORMATION_CLASS",
    "PHANDLE",
    "PLSA_REFERENCED_DOMAIN_LIST",
    "PLSA_TRANSLATED_NAME",
    "ProcessAccess",
    "PROCESS_BASIC_INFORMATION" "PROCESS_EXTENDED_BASIC_INFORMATION",
    "PROCESSINFOCLASS",
    "PROCESS_SESSION_INFORMATION" "ProcessToken",
    "PUBLIC_OBJECT_TYPE_INFORMATION",
    "PULONG",
    "PUNICODE_STRING",
    "PVOID",
    "SID_AND_ATTRIBUTES",
    "SID_NAME_USE",
    "SYSTEM_HANDLE_INFORMATION_EX",
    "SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX",
    "SYSTEM_INFORMATION_CLASS",
    "SYSTEM_PROCESS_INFORMATION",
    "SYSTEM_THREAD_INFORMATION",
    "TOKEN_PRIVILEGES",
    "TOKEN_USER",
    "ULONG",
    "UNICODE_STRING",
    "USHORT",
    "WCHAR",
    "WTS_SESSION_INFOW",
]
