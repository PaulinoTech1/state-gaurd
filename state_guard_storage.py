"""Local-file primitives. Locks do not protect a hostile, writable directory."""
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import stat
import uuid

MAX_BYTES = 4 * 1024 * 1024


if os.name == "nt":
    import ctypes
    from ctypes import wintypes as w
    import msvcrt

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("length", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]

    def api(dll, name, args, result=w.BOOL):
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
    get_owner = api(security, "GetSecurityDescriptorOwner", [w.LPVOID, ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.BOOL)])
    get_group = api(security, "GetSecurityDescriptorGroup", [w.LPVOID, ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.BOOL)])
    get_dacl = api(security, "GetSecurityDescriptorDacl", [w.LPVOID, ctypes.POINTER(w.BOOL), ctypes.POINTER(w.LPVOID), ctypes.POINTER(w.BOOL)])
    set_named_security = api(security, "SetNamedSecurityInfoW", [w.LPWSTR, ctypes.c_int, w.DWORD, w.LPVOID, w.LPVOID, w.LPVOID, w.LPVOID], w.DWORD)
    set_file_info = api(kernel, "SetFileInformationByHandle", [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD])
    drive_type = api(kernel, "GetDriveTypeW", [w.LPCWSTR], w.UINT)
    volume_info = api(kernel, "GetVolumeInformationW", [w.LPCWSTR, w.LPWSTR, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD), w.LPWSTR, w.DWORD])
    class StreamInfo(ctypes.Structure):
        _fields_ = [("size", ctypes.c_longlong), ("name", w.WCHAR * 296)]
    first_stream = api(kernel, "FindFirstStreamW", [w.LPCWSTR, ctypes.c_int, ctypes.POINTER(StreamInfo), w.DWORD], w.HANDLE)
    next_stream = api(kernel, "FindNextStreamW", [w.HANDLE, ctypes.POINTER(StreamInfo)])
    close_search = api(kernel, "FindClose", [w.HANDLE])

    def checked(result):
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())
        return result

    def user_sid():
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

    def descriptor(path, information=4):
        size = w.DWORD()
        get_security(str(path), information, None, 0, ctypes.byref(size))
        if not size.value:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(size.value)
        checked(get_security(str(path), information, buffer, size, ctypes.byref(size)))
        return buffer

    def private_acl(path):
        value = w.LPWSTR()
        checked(to_sddl(descriptor(path), 1, 4, ctypes.byref(value), None))
        try:
            sid = user_sid()
            return value.value in (
                f"D:P(A;;FA;;;SY)(A;;FA;;;{sid})",
                f"D:P(A;;FA;;;{sid})(A;;FA;;;SY)",
            )
        finally:
            local_free(ctypes.cast(value, w.HLOCAL))

    def windows_open(path, create=False, writable=False, private=False):
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
                    raise FileExistsError("Recovery or staging file already exists", str(path))
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

    def windows_replace(source, target):
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


def local_path(path):
    target = Path(os.path.abspath(path))
    if os.name == "nt" and (str(target).startswith("\\\\") or ":" in str(target)[2:]):
        raise ValueError("Use a local file, not a network path or alternate data stream")
    for part in (target, *target.parents):
        if os.name == "nt" and part.name.endswith((".", " ")):
            raise ValueError("Windows paths ending in dots or spaces are not supported")
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Linked paths and Windows reparse points are not supported")
    return target


def regular(info):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Use a regular file without hard links")


def bounded_read(handle):
    handle.seek(0)
    raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("File exceeds the 4 MiB limit")
    return raw


@contextmanager
def open_regular(path, writable=False, private=False):
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
            raise ValueError("File identity changed while opening")
        if private:
            if os.name == "nt":
                allowed = private_acl(target)
            else:
                allowed = info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
            if not allowed:
                raise ValueError("Recovery/lock file permissions are not private to this user")
        yield handle


def create_private(path, raw):
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


def writable_location(target):
    if os.name == "nt":
        filesystem = ctypes.create_unicode_buffer(32)
        checked(volume_info(target.anchor, None, 0, None, None, None, filesystem, 32))
        if drive_type(target.anchor) != 3 or filesystem.value != "NTFS":
            raise ValueError("Remediation requires a local fixed NTFS volume on Windows")
    else:
        for directory in (target.parent, *target.parent.parents):
            info = directory.stat()
            # Sticky /tmp-style ancestors cannot rename a child owned by this user.
            if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
                raise ValueError("Remediation requires ancestors without group/other write access")


@contextmanager
def operation_lock(path):
    target = local_path(path).resolve(strict=True)
    writable_location(target)
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
            raise ValueError("Another State Guard operation holds the config lock") from exc
        try:
            yield target
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    # Keep the stable inode: deleting the sidecar enables a split-lock race.


@contextmanager
def snapshot(path):
    with open_regular(path) as handle:
        if os.name == "nt":
            info = os.fstat(handle.fileno())
            if getattr(info, "st_file_attributes", 0) & (0x1 | 0x800 | 0x4000):
                raise ValueError("Remediation does not support read-only, compressed or encrypted files")
            stream = StreamInfo()
            search = first_stream(str(path), 0, ctypes.byref(stream), 0)
            if search == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                while True:
                    if stream.name != "::$DATA":
                        raise ValueError("Remediation does not support alternate data streams")
                    if not next_stream(search, ctypes.byref(stream)):
                        if ctypes.get_last_error() != 38:  # ERROR_HANDLE_EOF
                            raise ctypes.WinError(ctypes.get_last_error())
                        break
            finally:
                close_search(search)
        if os.name != "nt":
            import fcntl
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise ValueError("Config is locked by another writer") from exc
        yield bounded_read(handle), os.fstat(handle.fileno())


def sync_directory(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def assert_unchanged(path, raw, info):
    with open_regular(path) as handle:
        current = os.fstat(handle.fileno())
        if (current.st_dev, current.st_ino, current.st_mtime_ns, current.st_ctime_ns) != (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns) or bounded_read(handle) != raw:
            raise ValueError("Config changed during preparation; replacement refused")


def replace_file(source, target):
    if os.name == "nt":
        windows_replace(source, target)
    else:
        os.replace(source, target)


def atomic_update(path, raw, updated, info):
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
            acl_text = w.LPWSTR()
            checked(to_sddl(original, 1, 4, ctypes.byref(acl_text), None))
            try:
                flag = 0x80000000 if acl_text.value.startswith("D:P") else 0x20000000
            finally:
                local_free(ctypes.cast(acl_text, w.HLOCAL))
            owner, group, dacl = w.LPVOID(), w.LPVOID(), w.LPVOID()
            defaulted, present = w.BOOL(), w.BOOL()
            checked(get_owner(original, ctypes.byref(owner), ctypes.byref(defaulted)))
            checked(get_group(original, ctypes.byref(group), ctypes.byref(defaulted)))
            checked(get_dacl(original, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)))
            if not present or not dacl:
                raise ValueError("Config requires an explicit access-control list")
            error = set_named_security(str(temporary), 1, 7 | flag, owner, group, dacl, None)
            if error:
                raise ctypes.WinError(error)
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
                raise ValueError("Staging verification failed")
            os.fsync(handle.fileno())
        assert_unchanged(target, raw, info)
        replace_file(temporary, target)
        created = False
        sync_directory(target.parent)
        with open_regular(target) as handle:
            if bounded_read(handle) != updated:
                raise ValueError("Post-replacement verification failed; use rollback after inspection")
    finally:
        if created:
            temporary.unlink()
