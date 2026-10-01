"""Local-file primitives. Locks do not protect a hostile, writable directory."""
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import stat
from typing import Any, BinaryIO, Callable, Iterator
import uuid

MAX_BYTES = 4 * 1024 * 1024
PathLike = str | os.PathLike[str]


if os.name == "nt":
    import ctypes
    from ctypes import wintypes as w
    import msvcrt

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("length", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]

    class AclSizeInformation(ctypes.Structure):
        _fields_ = [("ace_count", w.DWORD), ("bytes_in_use", w.DWORD), ("bytes_free", w.DWORD)]

    class AceHeader(ctypes.Structure):
        _fields_ = [("type", ctypes.c_ubyte), ("flags", ctypes.c_ubyte), ("size", w.WORD)]

    class AccessAllowedAce(ctypes.Structure):
        _fields_ = [("header", AceHeader), ("mask", w.DWORD), ("sid_start", w.DWORD)]

    def api(dll: Any, name: str, args: list[Any], result: Any = w.BOOL) -> Callable[..., Any]:
        """Bind a Windows API function with explicit argument and result types."""
        function = getattr(dll, name)
        function.argtypes, function.restype = args, result
        return function

    create_file = api(kernel, "CreateFileW", [w.LPCWSTR, w.DWORD, w.DWORD, ctypes.POINTER(SecurityAttributes), w.DWORD, w.DWORD, w.HANDLE], w.HANDLE)
    close_handle = api(kernel, "CloseHandle", [w.HANDLE])
    local_free = api(kernel, "LocalFree", [w.HLOCAL], w.HLOCAL)
    get_process = api(kernel, "GetCurrentProcess", [], w.HANDLE)
    open_token = api(security, "OpenProcessToken", [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)])
    token_info = api(security, "GetTokenInformation", [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)])
    sid_string = api(security, "ConvertSidToStringSidW", [w.LPVOID, ctypes.POINTER(w.LPWSTR)])
    from_sddl = api(security, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [w.LPCWSTR, w.DWORD, ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.DWORD)])
    to_sddl = api(security, "ConvertSecurityDescriptorToStringSecurityDescriptorW", [w.LPVOID, w.DWORD, w.DWORD, ctypes.POINTER(w.LPWSTR), ctypes.POINTER(w.DWORD)])
    get_security = api(security, "GetFileSecurityW", [w.LPCWSTR, w.DWORD, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)])
    set_security = api(security, "SetFileSecurityW", [w.LPCWSTR, w.DWORD, w.LPVOID])
    get_dacl = api(security, "GetSecurityDescriptorDacl", [w.LPVOID, ctypes.POINTER(w.BOOL), ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.BOOL)])
    get_control = api(security, "GetSecurityDescriptorControl", [w.LPVOID, ctypes.POINTER(w.WORD), ctypes.POINTER(w.DWORD)])
    get_acl_information = api(security, "GetAclInformation", [w.LPVOID, w.LPVOID, w.DWORD, ctypes.c_int])
    get_ace = api(security, "GetAce", [w.LPVOID, w.DWORD, ctypes.POINTER(w.LPVOID)])
    set_file_info = api(kernel, "SetFileInformationByHandle", [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD])
    drive_type = api(kernel, "GetDriveTypeW", [w.LPCWSTR], w.UINT)
    volume_info = api(kernel, "GetVolumeInformationW", [w.LPCWSTR, w.LPWSTR, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD), w.LPWSTR, w.DWORD])
    class StreamInfo(ctypes.Structure):
        _fields_ = [("size", ctypes.c_longlong), ("name", w.WCHAR * 296)]
    first_stream = api(kernel, "FindFirstStreamW", [w.LPCWSTR, ctypes.c_int, ctypes.POINTER(StreamInfo), w.DWORD], w.HANDLE)
    next_stream = api(kernel, "FindNextStreamW", [w.HANDLE, ctypes.POINTER(StreamInfo)])
    close_search = api(kernel, "FindClose", [w.HANDLE])

    def checked(result: Any) -> Any:
        """Return a successful Windows API result or raise its native error."""
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())
        return result

    def user_sid() -> str:
        """Return the current Windows user's SID string."""
        token = w.HANDLE()
        checked(open_token(get_process(), 0x0008, ctypes.byref(token)))
        try:
            size = w.DWORD()
            token_info(token, 1, None, 0, ctypes.byref(size))
            buffer = ctypes.create_string_buffer(size.value)
            checked(token_info(token, 1, buffer, size, ctypes.byref(size)))
            sid = ctypes.cast(buffer, ctypes.POINTER(w.LPVOID))[0]
            value = w.LPWSTR()
            checked(sid_string(sid, ctypes.byref(value)))
            try:
                return value.value
            finally:
                local_free(ctypes.cast(value, w.HLOCAL))
        finally:
            close_handle(token)

    def descriptor(path: PathLike, information: int = 4) -> Any:
        """Read a Windows security descriptor for the requested information mask."""
        size = w.DWORD()
        get_security(str(path), information, None, 0, ctypes.byref(size))
        if not size.value:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(size.value)
        checked(get_security(str(path), information, buffer, size, ctypes.byref(size)))
        return buffer

    def _sid_text(pointer: w.LPVOID) -> str:
        """Convert a Windows SID pointer to its stable string form."""
        value = w.LPWSTR()
        checked(sid_string(pointer, ctypes.byref(value)))
        try:
            return value.value
        finally:
            local_free(ctypes.cast(value, w.HLOCAL))

    def private_acl_details(path: PathLike) -> tuple[bool, str]:
        """Validate a protected DACL and return sanitized ACE diagnostics."""
        security_descriptor = descriptor(path)
        control, revision = w.WORD(), w.DWORD()
        checked(get_control(security_descriptor, ctypes.byref(control), ctypes.byref(revision)))
        protected = bool(control.value & 0x1000)  # SE_DACL_PROTECTED
        present, defaulted, dacl = w.BOOL(), w.BOOL(), w.LPVOID()
        checked(get_dacl(security_descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)))
        if not present or not dacl:
            return False, f"protected={protected}; DACL is missing or null"

        size = AclSizeInformation()
        checked(get_acl_information(dacl, ctypes.byref(size), ctypes.sizeof(size), 2))  # AclSizeInformation
        trusted = {user_sid(), "S-1-5-18"}  # current user and SYSTEM
        deny_types = {1, 6, 10, 12}
        entries: list[str] = []
        allowed = protected
        for index in range(size.ace_count):
            pointer = w.LPVOID()
            checked(get_ace(dacl, index, ctypes.byref(pointer)))
            header = ctypes.cast(pointer, ctypes.POINTER(AceHeader)).contents
            if header.flags & 0x08:  # INHERIT_ONLY_ACE
                entries.append(f"type={header.type},flags=0x{header.flags:02x},inherit-only")
                continue
            if header.type in deny_types:
                entries.append(f"type={header.type},flags=0x{header.flags:02x},deny")
                continue
            if header.type != 0:  # Fail closed for allow-object, callback, and unknown ACE layouts.
                entries.append(f"type={header.type},flags=0x{header.flags:02x},unsupported")
                allowed = False
                continue
            ace = ctypes.cast(pointer, ctypes.POINTER(AccessAllowedAce)).contents
            sid_pointer = w.LPVOID(pointer.value + AccessAllowedAce.sid_start.offset)
            trustee = _sid_text(sid_pointer)
            entries.append(f"type=allow,flags=0x{header.flags:02x},mask=0x{ace.mask:08x},trustee={trustee}")
            if trustee not in trusted:
                allowed = False
        return allowed, f"protected={protected}; ACEs=[{'; '.join(entries)}]"

    def private_acl(path: PathLike) -> bool:
        """Return whether a file DACL grants access only to trusted principals."""
        return private_acl_details(path)[0]

    def windows_open(
        path: PathLike,
        create: bool = False,
        writable: bool = False,
        private: bool = False,
    ) -> int:
        """Open a Windows file with State Guard's sharing and optional ACL rules."""
        pointer = w.LPVOID()
        attributes = None
        if private:
            checked(from_sddl(f"D:P(A;;FA;;;SY)(A;;FA;;;{user_sid()})", 1, ctypes.byref(pointer), None))
            attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), pointer, False)
        try:
            access = 0x80000000 | (0x40000000 if writable else 0)
            # Snapshots deny write sharing; lock sidecars allow other lockers.
            share = 3 if writable else 5
            handle = create_file(str(path), access, share, ctypes.byref(attributes) if attributes else None,
                                 1 if create else 3, 0x00200000, None)
            if handle == ctypes.c_void_p(-1).value:
                error = ctypes.get_last_error()
                if error in (80, 183):
                    raise FileExistsError("Recovery or staging file already exists; inspect existing recovery files before retrying.")
                raise ctypes.WinError(error)
            try:
                fd = msvcrt.open_osfhandle(handle, (os.O_RDWR if writable else os.O_RDONLY) | os.O_BINARY)
            except BaseException:
                close_handle(handle)
                raise
            return fd
        finally:
            if pointer:
                local_free(pointer)

    def windows_replace(source: PathLike, target: PathLike) -> None:
        """Replace a Windows target by handle while its snapshot remains open."""
        # Rename the source by handle so the target can stay open denying writers.
        name = str(target)
        class RenameInfo(ctypes.Structure):
            _fields_ = [("replace", w.BOOL), ("root", w.HANDLE),
                        ("length", w.DWORD), ("name", w.WCHAR * (len(name.encode("utf-16-le")) // 2 + 1))]
        # FileRenameInfoEx: REPLACE_IF_EXISTS | POSIX_SEMANTICS permits replacement
        # while our write-denying read snapshot still holds the original inode.
        information = RenameInfo(3, None, len(name.encode("utf-16-le")), name)
        handle = create_file(str(source), 0x00010000, 7, None, 3, 0x00200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            checked(set_file_info(handle, 22, ctypes.byref(information), ctypes.sizeof(information)))
        finally:
            close_handle(handle)


def local_path(path: PathLike) -> Path:
    """Resolve an absolute local path and reject links and Windows reparse paths."""
    target = Path(os.path.abspath(path))
    if os.name == "nt" and (str(target).startswith("\\\\") or ":" in str(target)[2:]):
        raise ValueError("A local file is required; move the config off network storage and remove alternate data-stream syntax.")
    for part in (target, *target.parents):
        if os.name == "nt" and part.name.endswith((".", " ")):
            raise ValueError("Windows path components cannot end in dots or spaces; rename the file or directory and retry.")
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Linked paths and Windows reparse points are unsupported; select the real local file.")
    return target


def regular(info: os.stat_result) -> None:
    """Require one regular file with a single hard link."""
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("A single-link regular file is required; remove hard links or select the original file.")


def bounded_read(handle: BinaryIO) -> bytes:
    """Read a file from the start while enforcing the size limit."""
    handle.seek(0)
    raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("File exceeds the 4 MiB limit; reduce the config size before retrying.")
    return raw


@contextmanager
def open_regular(
    path: PathLike,
    writable: bool = False,
    private: bool = False,
) -> Iterator[BinaryIO]:
    """Open and identity-check a regular file without following links."""
    target = local_path(path)
    regular(target.lstat())
    if os.name == "nt":
        fd = windows_open(target, writable=writable)
    else:
        fd = os.open(target, (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r+b" if writable else "rb") as handle:
        info = os.fstat(handle.fileno())
        regular(info)
        if (info.st_dev, info.st_ino) != (target.stat().st_dev, target.stat().st_ino):
            raise ValueError("File identity changed while opening; stop concurrent file replacement and retry.")
        if private:
            if os.name == "nt":
                allowed, details = private_acl_details(target)
            else:
                allowed = info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
            if not allowed:
                message = "Recovery or lock-file permissions are too broad; restrict access to the current user and retry."
                if os.name == "nt":
                    message += f" Found {details}. Expected a protected DACL with applicable allow ACEs only for the current user or SYSTEM."
                raise ValueError(message)
        yield handle


def create_private(path: PathLike, raw: bytes) -> None:
    """Create, flush, and close a new user-private file."""
    target = local_path(path)
    if os.name == "nt":
        fd = windows_open(target, create=True, writable=True, private=True)
    else:
        fd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w+b") as handle:
            if os.name != "nt":
                os.fchmod(handle.fileno(), 0o600)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        target.unlink()
        raise


def writable_location(target: Path) -> None:
    """Require a supported local filesystem and trusted directory chain."""
    if os.name == "nt":
        filesystem = ctypes.create_unicode_buffer(32)
        checked(volume_info(target.anchor, None, 0, None, None, None, filesystem, 32))
        if drive_type(target.anchor) != 3 or filesystem.value != "NTFS":
            raise ValueError("Windows remediation requires a local fixed NTFS volume; move the config to supported storage.")
    else:
        for directory in (target.parent, *target.parent.parents):
            info = directory.stat()
            # Sticky /tmp-style ancestors cannot rename a child owned by this user.
            if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
                raise ValueError("A parent directory is group- or world-writable; restrict its permissions before remediation.")


@contextmanager
def operation_lock(path: PathLike) -> Iterator[Path]:
    """Serialize cooperating State Guard operations for one config."""
    target = local_path(path).resolve(strict=True)
    writable_location(target)
    if os.name == "nt":
        validate_windows_file(target)
    lock = target.with_name(target.name + ".state-guard.lock")
    try:
        create_private(lock, b"\0")
    except FileExistsError:
        pass
    with open_regular(lock, writable=True, private=True) as handle:
        try:
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ValueError("Another State Guard operation holds the config lock; wait for it to finish and retry.") from exc
        try:
            yield target
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    # Keep the stable inode: deleting the sidecar enables a split-lock race.


def validate_windows_file(path: PathLike, info: os.stat_result | None = None) -> None:
    """Reject Windows attributes and streams that remediation cannot preserve."""
    if info is None:
        info = Path(path).stat()
    if getattr(info, "st_file_attributes", 0) & (0x1 | 0x800 | 0x4000):
        raise ValueError("Windows remediation cannot preserve this read-only, compressed, or encrypted file; use a supported copy.")
    stream = StreamInfo()
    search = first_stream(str(path), 0, ctypes.byref(stream), 0)
    if search == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        while True:
            if stream.name != "::$DATA":
                raise ValueError("Windows remediation cannot preserve alternate data streams; remove or migrate them before retrying.")
            if not next_stream(search, ctypes.byref(stream)):
                if ctypes.get_last_error() != 38:  # ERROR_HANDLE_EOF
                    raise ctypes.WinError(ctypes.get_last_error())
                break
    finally:
        close_search(search)


@contextmanager
def snapshot(path: PathLike) -> Iterator[tuple[bytes, os.stat_result]]:
    """Hold and return a verified snapshot suitable for guarded replacement."""
    with open_regular(path) as handle:
        if os.name == "nt":
            validate_windows_file(path, os.fstat(handle.fileno()))
        if os.name != "nt":
            import fcntl
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise ValueError("Another writer holds the config lock; stop the owning application and retry.") from exc
        yield bounded_read(handle), os.fstat(handle.fileno())


def sync_directory(path: PathLike) -> None:
    """Flush a POSIX directory entry after replacement; no-op on Windows."""
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def assert_unchanged(path: PathLike, raw: bytes, info: os.stat_result) -> None:
    """Refuse replacement if identity, metadata, or bytes changed."""
    with open_regular(path) as handle:
        current = os.fstat(handle.fileno())
        if (current.st_dev, current.st_ino, current.st_mtime_ns, current.st_ctime_ns) != (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns) or bounded_read(handle) != raw:
            raise ValueError("Config changed during preparation; stop the owning application, review its changes, and retry.")


def replace_file(source: PathLike, target: PathLike) -> None:
    """Replace a target with the platform-specific atomic rename primitive."""
    if os.name == "nt":
        windows_replace(source, target)
    else:
        os.replace(source, target)


def atomic_update(
    path: PathLike,
    raw: bytes,
    updated: bytes,
    info: os.stat_result,
) -> None:
    """Stage, verify, and replace a config while preserving platform metadata."""
    target = local_path(path)
    temporary = target.with_name("." + target.name + ".state-guard-" + uuid.uuid4().hex + ".tmp")
    created = False
    try:
        create_private(temporary, updated)
        created = True
        if os.name == "nt":
            # Preserve owner, group and protected/unprotected DACL. Fail closed if
            # this user cannot retain the original security descriptor.
            original = descriptor(target, 7)
            dacl, present, defaulted = w.LPVOID(), w.BOOL(), w.BOOL()
            checked(get_dacl(original, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)))
            if not present or not dacl:
                raise ValueError("Config has no explicit Windows access-control list; set one before remediation.")
            checked(set_security(str(temporary), 7, original))
        else:
            os.chown(temporary, info.st_uid, info.st_gid)
            shutil.copystat(target, temporary, follow_symlinks=False)
            # copystat may silently skip unsupported security xattrs. Explicitly
            # copy each original attribute and refuse an unpreserved value.
            for name in os.listxattr(target, follow_symlinks=False):
                value = os.getxattr(target, name, follow_symlinks=False)
                os.setxattr(temporary, name, value, follow_symlinks=False)
        with open_regular(temporary, writable=True) as handle:
            if bounded_read(handle) != updated:
                raise ValueError("Staging-file verification failed; check storage health and available space before retrying.")
            os.fsync(handle.fileno())
        assert_unchanged(target, raw, info)
        replace_file(temporary, target)
        created = False
        sync_directory(target.parent)
        with open_regular(target) as handle:
            if bounded_read(handle) != updated:
                raise ValueError("Replacement verification failed; stop the owning application, inspect both files, then use rollback.")
    finally:
        if created:
            temporary.unlink()
