#  temporary root shell

This tool targets compatible  builds with:

- Android 8.1.0 / API 27
- MSM8953
- vulnerable Binder driver (CVE-2019-2215)

It does not require an exact kernel release string. Compatibility still depends
on the vulnerable Binder implementation and the kernel structure layouts used
by the exploit, so use it only on builds known to be compatible.

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

At the `cube-root#` prompt, enter ordinary Android shell commands. Use `exit`
to end the session. The batch file removes the temporary on-device binary
after the session exits.

## Manual use

```text
adb -s ADB_SERIAL_OR_ADDRESS push cube_temp_root /data/local/tmp/cube_temp_root
adb -s ADB_SERIAL_OR_ADDRESS shell chmod 755 /data/local/tmp/cube_temp_root
adb -s ADB_SERIAL_OR_ADDRESS shell -t /data/local/tmp/cube_temp_root root-shell
```

For a single non-interactive command:

```text
adb -s ADB_SERIAL_OR_ADDRESS shell /data/local/tmp/cube_temp_root root-command id
```

## Security model and limitations

The shell has UID/GID 0 and full Linux capabilities, but deliberately retains
the `u:r:shell:s0` SELinux domain. SELinux stays Enforcing, so accesses denied
to the normal shell domain can still fail even with UID 0. The separate
validated aboot dumper uses a narrowly scoped PID 1 credential handoff for
block-device reads.

The tool dynamically locates `task_struct`, the task list, private credentials,
and PID 1 credentials. It restores the child credential bytes before exiting.
It does not modify any flash partition or install persistent root.

Always leave the prompt with `exit`. A failed UAF race can reboot the device.
