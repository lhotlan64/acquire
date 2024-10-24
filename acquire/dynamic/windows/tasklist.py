from __future__ import annotations

import ctypes
from ctypes.wintypes import (
    BOOL,
    DWORD,
    HANDLE,
    LPDWORD,
    LPVOID,
    LPWSTR,
    PHANDLE,
    PULONG,
    ULONG,
    USHORT,
)
from enum import IntEnum
from typing import ClassVar

NTSTATUS = ULONG
ULONG_PTR = ctypes.c_size_t
SIZE_T = ctypes.c_size_t
PDWORD = ctypes.POINTER(DWORD)


CURRENT_PROCESS = HANDLE(-1)
POLICY_LOOKUP_NAMES = 0x00000800
TOKEN_QUERY = 0x0008
TOKEN_ALL_ACCESS = 0xF01FF
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
MAX_PATH = 260
MAX_BUFFER_SIZE = 256 * 1024 * 1024

STATUS_SUCCESS = 0
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

SYSTEM_IDLE_PROCESS_ID = 0
SYSTEM_PROCESS_ID = 4
SYSTEM_IDLE_PROCESS_NAME = "System Idle Process"


class PROCESSINFOCLASS(IntEnum):
    PROCESSBASICINFORMATION = 0
    PROCESSVMCOUNTERS = 3
    PROCESSTIMES = 4
    PROCESSSESSIONINFORMATION = 24
    PROCESSIMAGEFILENAME = 27
    PROCESSWINDOWINFORMATION = 50


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


class LUID(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("LowPart", DWORD),
        ("HighPart", DWORD),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


class WTS_SESSION_INFOW(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("SessionId", DWORD),
        ("Padding", DWORD),
        ("pWinStationName", LPWSTR),
        ("State", DWORD),
    ]


class UNICODE_STRING(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", LPWSTR),
    ]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("Sid", LPVOID),
        ("Attributes", DWORD),
    ]


class TOKEN_USER(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("User", SID_AND_ATTRIBUTES),
    ]


class LSA_OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
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
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("ExitStatus", NTSTATUS),
        ("PebBaseAddress", LPVOID),
        ("AffinityMask", ULONG_PTR),
        ("BasePriority", ULONG),
        ("UniqueProcessId", HANDLE),
        ("InheritedFromUniqueProcessId", HANDLE),
    ]


class PROCESS_EXTENDED_BASIC_INFORMATION(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("Size", SIZE_T),
        ("BasicInfo", PROCESS_BASIC_INFORMATION),
        ("Flags", ULONG),  # of interest is IsFrozen (bit 4)
    ]


class PROCESS_SESSION_INFORMATION(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("SessionId", ULONG),
    ]


class LSA_TRANSLATED_NAME(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("Use", ULONG),
        ("Name", UNICODE_STRING),
        ("DomainIndex", ULONG),
    ]


class LSA_TRUST_INFORMATION(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("Name", UNICODE_STRING),
        ("Sid", LPVOID),
    ]


class LSA_REFERENCED_DOMAIN_LIST(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("Entries", ULONG),
        ("Domains", ctypes.POINTER(LSA_TRUST_INFORMATION) * 1),
    ]


class LARGE_INTEGER(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("LowPart", DWORD),
        ("HighPart", DWORD),
    ]


class CLIENT_ID(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
        ("UniqueProcess", HANDLE),
        ("UniqueThread", HANDLE),
    ]


class SYSTEM_THREAD_INFORMATION(ctypes.Structure):
    _fields_: ClassVar[list[tuple[str, type]]] = [
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
    _fields_: ClassVar[list[tuple[str, type]]] = [
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


PLSA_TRANSLATED_NAME = ctypes.POINTER(LSA_TRANSLATED_NAME)
PLSA_REFERENCED_DOMAIN_LIST = ctypes.POINTER(LSA_REFERENCED_DOMAIN_LIST)

advapi32 = ctypes.WinDLL("advapi32.dll")
kernel32 = ctypes.WinDLL("kernel32.dll")
ntdll = ctypes.WinDLL("ntdll.dll")
wtsapi32 = ctypes.WinDLL("wtsapi32.dll")

OpenProcessToken = advapi32.OpenProcessToken
OpenProcessToken.argtypes = [HANDLE, DWORD, PHANDLE]
OpenProcessToken.restype = BOOL

GetTokenInformation = advapi32.GetTokenInformation
GetTokenInformation.argtypes = [HANDLE, ULONG, LPVOID, DWORD, PDWORD]
GetTokenInformation.restype = BOOL

LookupPrivilegeValueW = advapi32.LookupPrivilegeValueW
LookupPrivilegeValueW.argtypes = [LPVOID, LPWSTR, LPVOID]
LookupPrivilegeValueW.restype = BOOL

AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
AdjustTokenPrivileges.argtypes = [HANDLE, BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), DWORD, LPVOID, PDWORD]
AdjustTokenPrivileges.restype = BOOL

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

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [DWORD, BOOL, DWORD]
OpenProcess.restype = HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [HANDLE]
CloseHandle.restype = BOOL

GetProcessId = kernel32.GetProcessId
GetProcessId.argtypes = [HANDLE]
GetProcessId.restype = DWORD

try:
    EnumProcesses = kernel32.EnumProcesses
except AttributeError:
    EnumProcesses = kernel32.K32EnumProcesses
EnumProcesses.argtypes = [LPVOID, DWORD, LPDWORD]
EnumProcesses.restype = BOOL

WTSEnumerateSessionsW = wtsapi32.WTSEnumerateSessionsW
WTSEnumerateSessionsW.argtypes = [HANDLE, DWORD, DWORD, LPVOID, LPDWORD]
WTSEnumerateSessionsW.restype = BOOL

WTSFreeMemory = wtsapi32.WTSFreeMemory
WTSFreeMemory.argtypes = [LPVOID]
WTSFreeMemory.restype = None

NtQueryInformationProcess = ntdll.NtQueryInformationProcess
NtQueryInformationProcess.argtypes = [HANDLE, DWORD, LPVOID, ULONG, PULONG]
NtQueryInformationProcess.restype = NTSTATUS

NtQuerySystemInformation = ntdll.NtQuerySystemInformation
NtQuerySystemInformation.argtypes = [DWORD, LPVOID, ULONG, PULONG]
NtQuerySystemInformation.restype = NTSTATUS


class Process:
    def __init__(
        self,
        pid: int,
        image_name: str,
        sess_id: int,
        sess_name: str,
        user: str,
        domain: str,
        state: str,
        mem_usage: int,
        ticks: int,
    ):
        self.pid = pid
        self.image_name = image_name
        self.session_id = sess_id
        self.session_name = sess_name
        self.user = user
        self.domain = domain
        self.state = state
        self.memory_usage = mem_usage
        self.cpu_ticks = ticks

    def __str__(self) -> str:
        return (
            f"Process(pid={self.pid}, img={self.image_name}, user={self.domain}\\{self.user}, "
            f"sess={self.session_name} ({self.session_id}), mem={self.memory_usage}, status={self.state}, "
            f"time={self.cpu_ticks})"
        )


def get_session_name_by_id(session_id: int) -> str | None:
    session_count = DWORD(0)
    sessions_buffer = ctypes.POINTER(WTS_SESSION_INFOW)()

    if WTSEnumerateSessionsW(HANDLE(0), 0, 1, ctypes.byref(sessions_buffer), ctypes.byref(session_count)) == False:
        return None

    sessions = ctypes.cast(sessions_buffer, ctypes.POINTER(WTS_SESSION_INFOW * session_count.value)).contents

    session_name = None
    for session in sessions:
        if session.SessionId == session_id:
            session_name = str(session.pWinStationName)
            break

    WTSFreeMemory(sessions_buffer)

    return session_name


def get_lsa_lookup_policy_handle() -> HANDLE | None:
    lookup_policy_handle = HANDLE(0)
    object_attributes = LSA_OBJECT_ATTRIBUTES()

    status = LsaOpenPolicy(
        LPVOID(0), ctypes.byref(object_attributes), POLICY_LOOKUP_NAMES, ctypes.byref(lookup_policy_handle)
    )

    if status != STATUS_SUCCESS:
        return None

    return lookup_policy_handle


def get_process_user_info(process: HANDLE) -> tuple[str, str] | None:
    needed = DWORD(0)
    token = HANDLE(0)
    names_ptr = PLSA_TRANSLATED_NAME()
    domains_ptr = PLSA_REFERENCED_DOMAIN_LIST()
    buffer = ctypes.create_string_buffer(512)

    lookup_policy_handle = get_lsa_lookup_policy_handle()
    if lookup_policy_handle is None:
        return (None, None)

    if OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)) == False:
        LsaClose(lookup_policy_handle)
        return (None, None)

    # TokenUser = 1
    status = GetTokenInformation(token, 1, buffer, len(buffer), ctypes.byref(needed))
    if status == False:
        LsaClose(lookup_policy_handle)
        CloseHandle(token)
        return (None, None)

    token_user = ctypes.cast(buffer, ctypes.POINTER(TOKEN_USER)).contents
    sid = LPVOID(token_user.User.Sid)

    status = LsaLookupSids(
        lookup_policy_handle, 1, ctypes.byref(sid), ctypes.byref(domains_ptr), ctypes.byref(names_ptr)
    )

    if status != STATUS_SUCCESS:
        LsaClose(lookup_policy_handle)
        CloseHandle(token)
        return (None, None)

    name = names_ptr.contents
    domains = domains_ptr.contents

    if name.Use in [SID_NAME_USE.INVALID, SID_NAME_USE.UNKNOWN]:
        LsaFreeMemory(domains_ptr)
        LsaFreeMemory(names_ptr)
        LsaClose(lookup_policy_handle)
        CloseHandle(token)
        return (None, None)

    domain = None
    username = None

    if name.DomainIndex >= 0:
        infos = ctypes.cast(
            ctypes.byref(domains.Domains), ctypes.POINTER(ctypes.POINTER(LSA_TRUST_INFORMATION) * domains.Entries)
        ).contents
        trust_info = infos[name.DomainIndex].contents
        domain = str(trust_info.Name.Buffer)

    username = str(name.Name.Buffer)

    LsaFreeMemory(domains_ptr)
    LsaFreeMemory(names_ptr)

    return (username, domain)


def get_process_state(process: HANDLE) -> str:
    needed = ULONG(0)
    pebi = PROCESS_EXTENDED_BASIC_INFORMATION()
    pebi.Size = ctypes.sizeof(pebi)

    status = NtQueryInformationProcess(
        process, PROCESSINFOCLASS.PROCESSBASICINFORMATION, ctypes.byref(pebi), ctypes.sizeof(pebi), ctypes.byref(needed)
    )

    if status != STATUS_SUCCESS:
        return "Unknown"

    # check if the IsFrozen bit is set, indicating a suspended process
    is_suspended = pebi.Flags & 0b1000

    if is_suspended:
        return "Suspended"

    return "Running"


def get_process_information(process: SYSTEM_PROCESS_INFORMATION) -> Process | None:
    process_id = process.UniqueProcessId if process.UniqueProcessId is not None else 0

    if process_id != SYSTEM_IDLE_PROCESS_ID:
        image_name = process.ImageName.Buffer
    else:
        image_name = SYSTEM_IDLE_PROCESS_NAME

    session_id = process.SessionId
    session_name = get_session_name_by_id(process.SessionId) or "Unknown"
    working_set_size = process.WorkingSetSize
    kernel_ticks = process.KernelTime.HighPart << 32 | process.KernelTime.LowPart
    user_ticks = process.UserTime.HighPart << 32 | process.UserTime.LowPart
    total_ticks = kernel_ticks + user_ticks

    process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, process_id)

    if process_handle is not None and process_id != SYSTEM_PROCESS_ID:
        user_context = get_process_user_info(process_handle)
        process_state = get_process_state(process_handle)
        CloseHandle(process_handle)
    else:
        if process_id in [SYSTEM_IDLE_PROCESS_ID, SYSTEM_PROCESS_ID]:
            user_context = ("SYSTEM", "NT AUTHORITY")
            process_state = "Running"
        else:
            user_context = ("<unknown>", "<unknown>")
            process_state = "Unknown"

    return Process(
        pid=process_id,
        image_name=image_name,
        sess_id=session_id,
        sess_name=session_name,
        user=user_context[0],
        domain=user_context[1],
        state=process_state,
        mem_usage=working_set_size,
        ticks=total_ticks,
    )


def get_active_process_list() -> list[Process]:
    needed = ULONG(0)
    buffer_size = 0x4000

    while buffer_size < MAX_BUFFER_SIZE:
        buffer = ctypes.create_string_buffer(buffer_size)

        # SystemProcessInformation = 5
        status = NtQuerySystemInformation(5, buffer, buffer_size, ctypes.byref(needed))

        if status != STATUS_INFO_LENGTH_MISMATCH:
            break

        buffer_size *= 2

    if status != STATUS_SUCCESS:
        return []

    process_addr = ctypes.addressof(buffer)
    processes: list[Process] = []

    while True:
        process = ctypes.cast(process_addr, ctypes.POINTER(SYSTEM_PROCESS_INFORMATION)).contents
        process_info = get_process_information(process)
        processes.append(process_info)

        if process.NextEntryOffset == 0:
            break

        process_addr += process.NextEntryOffset

    return processes


def ticks_to_timespan(ticks: int) -> str:
    ticks_per_ns = 10
    ticks_per_ms = ticks_per_ns * 1000
    ticks_per_sec = ticks_per_ms * 1000
    ticks_per_min = ticks_per_sec * 60
    ticks_per_hr = ticks_per_min * 60
    ticks_per_day = ticks_per_hr * 24

    ms = int(ticks / ticks_per_ms) % 1000
    sec = int(ticks / ticks_per_sec) % 60
    min = int(ticks / ticks_per_min) % 60
    hrs = int(ticks / ticks_per_hr) % 24
    days = int(ticks / ticks_per_day)

    return f"{days:02}:{hrs:02}:{min:02}:{sec:02}:{ms:03}"


def format_active_processes_as_csv(processes: list[Process]) -> str:
    quoted = lambda item: f'"{item}"'

    def formatter(process: Process) -> str:
        user = process.user if process.user else ""
        domain = process.domain if process.domain else ""
        domain_and_user = domain + "\\" + user
        working_set = f"{process.memory_usage / 1024.0:.2f} K"
        cpu_time = ticks_to_timespan(process.cpu_ticks)

        items = [
            process.image_name,
            process.pid,
            process.session_name,
            process.session_id,
            working_set,
            process.state,
            domain_and_user,
            cpu_time,
            "",  # we don't support the window title as of yet
        ]

        return ",".join([quoted(item) for item in items])

    header = [
        "Image Name",
        "PID",
        "Session Name",
        "Session#",
        "Mem Usage",
        "Status",
        "User Name",
        "CPU Time",
        "Window Title",
    ]

    header = ",".join(quoted(item) for item in header)
    rows = "\n".join(formatter(process) for process in processes)

    return header + "\n" + rows
