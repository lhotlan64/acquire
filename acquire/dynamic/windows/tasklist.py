from __future__ import annotations

import ctypes
from ctypes.wintypes import DWORD, HANDLE, LPVOID, ULONG

from acquire.dynamic.windows.advapi32 import (
    GetTokenInformation,
    LsaClose,
    LsaFreeMemory,
    LsaLookupSids,
    LsaOpenPolicy,
    OpenProcessToken,
)
from acquire.dynamic.windows.kernel32 import CloseHandle, OpenProcess
from acquire.dynamic.windows.ntdll import (
    NtQueryInformationProcess,
    NtQuerySystemInformation,
)
from acquire.dynamic.windows.types import (
    BOOL,
    HWND,
    LPARAM,
    LSA_OBJECT_ATTRIBUTES,
    LSA_TRUST_INFORMATION,
    NULL,
    PLSA_REFERENCED_DOMAIN_LIST,
    PLSA_TRANSLATED_NAME,
    PROCESS_EXTENDED_BASIC_INFORMATION,
    PROCESSINFOCLASS,
    SID_NAME_USE,
    SYSTEM_PROCESS_INFORMATION,
    TOKEN_USER,
    WINDOWINFO,
    WTS_SESSION_INFOW,
)
from acquire.dynamic.windows.user32 import (
    EnumChildWindows,
    GetParent,
    GetWindowInfo,
    GetWindowThreadProcessId,
    InternalGetWindowText,
    IsWindowVisible,
)
from acquire.dynamic.windows.wtsapi32 import WTSEnumerateSessionsW, WTSFreeMemory

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


class Process:
    def __init__(
        self,
        pid: int,
        image_name: str,
        sess_id: int,
        mem_usage: int,
        ticks: int,
        sess_name: str | None,
        user: str | None,
        domain: str | None,
        state: str | None,
        window_title: str | None,
    ):
        self.pid = pid
        self.image_name = image_name
        self.state = state
        self.session_id = sess_id
        self.cpu_ticks = ticks
        self.session_name = sess_name
        self.user = user
        self.domain = domain
        self.memory_usage = mem_usage
        self.window_title = window_title

    def __str__(self) -> str:
        return (
            f"Process(pid={self.pid}, img={self.image_name}, user={self.domain}\\{self.user}, "
            f"sess={self.session_name} ({self.session_id}), mem={self.memory_usage}, status={self.state}, "
            f"time={self.cpu_ticks}, title={self.window_title})"
        )


class MainWindowContext(ctypes.Structure):
    _fields_ = [
        ("ProcessId", HANDLE),
        ("Window", HANDLE),
    ]


@ctypes.WINFUNCTYPE(BOOL, HWND, LPARAM)
def get_process_main_window_callback(hwnd: HWND, lparam: LPARAM) -> BOOL:
    ctx = ctypes.cast(lparam, ctypes.POINTER(MainWindowContext)).contents

    if IsWindowVisible(hwnd) is False:
        return True

    process_id = DWORD(0)
    GetWindowThreadProcessId(hwnd, ctypes.byref(process_id))

    if process_id.value != ctx.ProcessId:
        # it's not the process we're looking for
        return True

    parent = GetParent(hwnd)
    if parent is not None and IsWindowVisible(parent):
        # there's a visible parent so we're not the main window
        return True

    window_text = ctypes.create_unicode_buffer(32)
    if InternalGetWindowText(hwnd, window_text, len(window_text)) == 0:
        # the window does not have a title
        return True

    window_info = WINDOWINFO()
    window_info.cbSize = ctypes.sizeof(WINDOWINFO)

    if not GetWindowInfo(hwnd, ctypes.byref(window_info)):
        return True

    WS_DLGFRAME = 0x00400000
    if window_info.dwStyle & WS_DLGFRAME:
        ctx.Window = hwnd
        return False

    return True


def get_process_main_window(process_id: DWORD, process_handle: HANDLE) -> HWND:
    ctx = MainWindowContext()
    ctypes.memset(ctypes.addressof(ctx), 0, ctypes.sizeof(ctx))

    ctx.ProcessId = process_id
    ctx.Window = None

    lparam = LPARAM(ctypes.addressof(ctx))
    EnumChildWindows(NULL, get_process_main_window_callback, lparam)

    return ctx.Window


def get_process_window_title(process_id: DWORD, process_handle: HANDLE) -> str | None:
    hwnd = get_process_main_window(process_id, process_handle)
    if hwnd is None:
        return None

    buffer = ctypes.create_unicode_buffer(256)
    InternalGetWindowText(hwnd, buffer, 255)

    return str(buffer.value)


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
        window_title = get_process_window_title(process_id, process_handle)
        CloseHandle(process_handle)
    else:
        if process_id in [SYSTEM_IDLE_PROCESS_ID, SYSTEM_PROCESS_ID]:
            user_context = ("SYSTEM", "NT AUTHORITY")
            process_state = "Running"
        else:
            user_context = ("<unknown>", "<unknown>")
            process_state = "Unknown"
        window_title = None

    return Process(
        pid=process_id,
        image_name=image_name,
        sess_id=session_id,
        mem_usage=working_set_size,
        ticks=total_ticks,
        state=process_state,
        sess_name=session_name,
        user=user_context[0],
        domain=user_context[1],
        window_title=window_title,
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
        window_title = process.window_title if process.window_title else ""

        items = [
            process.image_name,
            process.pid,
            process.session_name,
            process.session_id,
            working_set,
            process.state,
            domain_and_user,
            cpu_time,
            window_title,
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
