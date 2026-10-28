# FirmHound Lab Firmware

This directory is the source fixture for `scripts/build_lab_firmware.py`.
It is intentionally vulnerable and must only be used as a local regression
sample. It does not implement a network listener or contact an external host.

The generated image contains deliberately unsafe paths for testing:

- command construction followed by `system()`;
- stack copies through `strcpy()`;
- user-controlled format strings through `printf()`;
- path construction followed by `fopen()`;
- shell `eval` in a CGI fixture.

The C source is copied into the generated rootfs under `usr/src/` so KLEE's
source-harness mode can use it as a transparent modelling input.
