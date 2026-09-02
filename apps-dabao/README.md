# Apps for Dabao

These are applications targeting a minimal set of Xous services for hardware configurations that are basically "just the chip".

The image flashed onto dabao was built using the following command:

`cargo xtask dabao dabao-console --no-timestamp --kernel-feature debug-proc`

## USB Hardware RNG

Build the USB hardware random-number source with:

`cargo xtask dabao bio-stream --no-timestamp --kernel-feature debug-proc`

The image implements the [ChaosKey](https://github.com/altusmetrum/chaoskey) USB HWRNG interface with
VID:PID `1d50:60c6`. Linux's in-tree `chaoskey` driver binds its vendor-specific bulk-IN endpoint to the
hardware random-number framework. Enable `CONFIG_HW_RANDOM_CHAOSKEY` or load `chaoskey`; random bytes are
then available from `/dev/hwrng`.

See [the Baochip README](../README-baochip.md) for more details.