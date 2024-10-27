from __future__ import annotations

import ctypes
from ctypes.wintypes import FILETIME, LONG, ULONG, WORD
from socket import inet_ntop

from acquire.dynamic.windows.kernel32 import (
    FileTimeToSystemTime,
    SystemTimeToTzSpecificLocalTime,
)
from acquire.dynamic.windows.types import (
    DWORD,
    LPDWORD,
    LPVOID,
    LPWSTR,
    SYSTEMTIME,
    WTS_CLIENT_ADDRESS,
    WTS_CONNECTSTATE_CLASS,
    WTS_INFO_CLASS,
    WTS_SESSION_INFOW,
    WTSINFOW,
)
from acquire.dynamic.windows.wtsapi32 import (
    WTS_CURRENT_SERVER_HANDLE,
    WTSEnumerateSessionsW,
    WTSFreeMemory,
    WTSQuerySessionInformationW,
)


class RDPSession:
    def __init__(
        self,
        session_id: int,
        state: str,
        username: str | None,
        domain: str | None,
        session_name: str | None,
        logontime: str | None,
        remote_address: str | None,
    ) -> RDPSession:
        self.session_id = session_id
        self.state = state
        self.username = username
        self.domain = domain
        self.session_name = session_name
        self.logontime = logontime
        self.remote_address = remote_address

    def __str__(self) -> str:
        return (
            f"RDPSession(session={self.session_name}({self.session_id}), user={self.username}, "
            f"domain={self.domain}, logon={self.logontime}, remote={self.remote_address}, state={self.state})"
        )


def query_session_information(session_id: int, cls: WTS_INFO_CLASS, cb) -> str | None:
    data = LPVOID(0)
    size = DWORD(0)

    status = WTSQuerySessionInformationW(
        WTS_CURRENT_SERVER_HANDLE, session_id, cls.value, ctypes.byref(data), ctypes.byref(size)
    )

    if status == False:
        return None

    result = cb(data)
    WTSFreeMemory(data)

    return result


def get_session_info_as_string_callback(data: LPVOID) -> str | None:
    value = str(ctypes.cast(data, LPWSTR).value)
    return value if len(value) else None


def get_session_info_session_state_callback(data: LPVOID) -> str:
    value = ctypes.cast(data, LPDWORD).contents
    state = WTS_CONNECTSTATE_CLASS(value.value)
    return state.name


def get_session_info_logontime_callback(data: LPVOID) -> str | None:
    info = ctypes.cast(data, ctypes.POINTER(WTSINFOW)).contents

    if info.LogonTime.LowPart == 0 and info.LogonTime.HighPart == 0:
        return None

    ft = FILETIME()
    ft.dwLowDateTime = info.LogonTime.LowPart
    ft.dwHighDateTime = info.LogonTime.HighPart

    st = SYSTEMTIME()
    FileTimeToSystemTime(ctypes.byref(ft), ctypes.byref(st))
    SystemTimeToTzSpecificLocalTime(LPVOID(0), ctypes.byref(st), ctypes.byref(st))

    return f"{st.wDay:02}/{st.wMonth:02}/{st.wYear} {st.wHour:02}:{st.wMinute:02}:{st.wSecond:02}"


def get_session_info_remoteaddr_callback(data: LPVOID) -> str | None:
    info = ctypes.cast(data, ctypes.POINTER(WTS_CLIENT_ADDRESS)).contents
    try:
        return inet_ntop(info.AddressFamily, bytes(info.Address[2:]))
    except ValueError:
        return None


def get_session_information(session_id: int) -> RDPSession:
    username = query_session_information(
        session_id,
        WTS_INFO_CLASS.WTSUserName,
        get_session_info_as_string_callback,
    )

    domain = query_session_information(
        session_id,
        WTS_INFO_CLASS.WTSDomainName,
        get_session_info_as_string_callback,
    )

    session_name = query_session_information(
        session_id,
        WTS_INFO_CLASS.WTSWinStationName,
        get_session_info_as_string_callback,
    )

    session_state = query_session_information(
        session_id,
        WTS_INFO_CLASS.WTSConnectState,
        get_session_info_session_state_callback,
    )

    logontime = query_session_information(
        session_id,
        WTS_INFO_CLASS.WTSSessionInfo,
        get_session_info_logontime_callback,
    )

    remote_addr = query_session_information(
        session_id,
        WTS_INFO_CLASS.WTSClientAddress,
        get_session_info_remoteaddr_callback,
    )

    return RDPSession(
        session_id=session_id,
        state=session_state,
        username=username,
        domain=domain,
        session_name=session_name,
        logontime=logontime,
        remote_address=remote_addr,
    )


def get_rdp_sessions() -> list[RDPSession]:
    sessions_info = LPVOID(0)
    session_count = DWORD(0)

    status = WTSEnumerateSessionsW(
        WTS_CURRENT_SERVER_HANDLE,
        0,
        1,
        ctypes.byref(sessions_info),
        ctypes.byref(session_count),
    )

    if status == False:
        return []

    sessions = ctypes.cast(sessions_info, ctypes.POINTER(WTS_SESSION_INFOW * session_count.value)).contents
    rdp_session = []
    for session in sessions:
        sess_info = get_session_information(session.SessionId)
        rdp_session.append(sess_info)

    WTSFreeMemory(sessions_info)

    return rdp_session
