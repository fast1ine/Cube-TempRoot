# Temporary root shell — CVE-2019-2215 study

A study and reimplementation of the CVE-2019-2215 Binder use-after-free
privilege escalation, based on the Google Project Zero proof-of-concept by
Jann Horn & Maddie Stone. It was verified on a single Android device I
lawfully own with:

- Android 8.1.0 / API 27
- MSM8953
- vulnerable Binder driver (CVE-2019-2215)

It does not require an exact kernel release string. Compatibility still depends
on the vulnerable Binder implementation and the kernel structure layouts used
by the exploit, so use it only on a device you own that is known to be
compatible.

## Build

No prebuilt binary is distributed — build `temp_root` from `temp_root.c`
yourself. All logic is in the single source file on purpose. Compile for
AArch64, e.g. with the cross-compiler toolchain in Android NDK r20:

```text
$NDK/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android27-clang \
    temp_root.c -O2 -o temp_root
```

Place the resulting `temp_root` next to `TempRoot.bat` before running it.

## Interactive use

Choose a target reported by `adb devices` and pass its serial or address
explicitly:

```bat
TempRoot.bat ADB_SERIAL_OR_ADDRESS
```

For network ADB, connect first if necessary and pass the same address:

```bat
adb connect DEVICE_IP:5555
TempRoot.bat DEVICE_IP:5555
```

At the `root#` prompt, enter ordinary Android shell commands. Use `exit`
to end the session. The batch file removes the temporary on-device binary
after the session exits.

## Manual use

```text
adb -s ADB_SERIAL_OR_ADDRESS push temp_root /data/local/tmp/temp_root
adb -s ADB_SERIAL_OR_ADDRESS shell chmod 755 /data/local/tmp/temp_root
adb -s ADB_SERIAL_OR_ADDRESS shell -t /data/local/tmp/temp_root root-shell
```

For a single non-interactive command:

```text
adb -s ADB_SERIAL_OR_ADDRESS shell /data/local/tmp/temp_root root-command id
```

## Security model and limitations

The shell has UID/GID 0 and full Linux capabilities, but deliberately retains
the `u:r:shell:s0` SELinux domain. SELinux stays Enforcing, so accesses denied
to the normal shell domain can still fail even with UID 0.

The tool dynamically locates `task_struct`, the task list, private credentials,
and PID 1 credentials. It restores the child credential bytes before exiting.
It does not modify any flash partition or install persistent root.

Always leave the prompt with `exit`. A failed UAF race can reboot the device.

## Credits

Derived from the Google Project Zero proof-of-concept for CVE-2019-2215 by
Jann Horn & Maddie Stone — Project Zero issue #1942
(https://bugs.chromium.org/p/project-zero/issues/detail?id=1942).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). This matches the licensing of
the upstream Project Zero proof-of-concept this work is derived from.

## Scope and intended use

Security-research code, published for study and reproducibility of a
documented, long-patched CVE. Use it only on a device you personally and
lawfully own, or are explicitly authorized to test. Do not use it against any
device you do not own or lack authorization to test.
