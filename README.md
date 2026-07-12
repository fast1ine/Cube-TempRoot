#  temporary root shell

This tool is specific to the tested  build:

- Android 8.1.0 / API 27
- kernel `4.9.82-perf`
- MSM8953
- vulnerable Binder driver (CVE-2019-2215)

## Interactive use

With network ADB at `192.168.0.40:5555`, run:

```bat
TempRoot.bat
```

For another ADB serial or address:

```bat
TempRoot.bat 192.168.0.40:5555
```

At the `cube-root#` prompt, enter ordinary Android shell commands. Use `exit`
to end the session. The batch file removes the temporary on-device binary
after the session exits.

## Manual use

```text
adb -s 192.168.0.40:5555 push cube_temp_root /data/local/tmp/cube_temp_root
adb -s 192.168.0.40:5555 shell chmod 755 /data/local/tmp/cube_temp_root
adb -s 192.168.0.40:5555 shell -t /data/local/tmp/cube_temp_root root-shell
```

For a single non-interactive command:

```text
adb -s 192.168.0.40:5555 shell /data/local/tmp/cube_temp_root root-command id
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
