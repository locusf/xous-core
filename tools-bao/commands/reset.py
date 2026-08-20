import sys
import logging

from utils.serial_utils import open_serial, safe_close


def cmd_reset(args) -> None:
    port = args.port
    baud = args.baud
    try:
        # open_serial(..., reset=True) asserts DTR+RTS, holds briefly, then
        # releases them — this pulses the board's reset line via the USB CDC
        # control signals.
        ser = open_serial(port, baud, timeout=0.2, reset=True)
    except Exception as e:
        logging.error(f"[bao] cannot open {port}: {e}")
        sys.exit(2)

    safe_close(ser)
    print(f"[bao] reset pulse (DTR/RTS) sent on {port}")
    sys.exit(0)


def register(subparsers) -> None:
    r = subparsers.add_parser(
        "reset",
        help="Toggle DTR/RTS on the serial port to reset the attached board"
    )
    r.add_argument("-p", "--port", required=True, help="Serial port (e.g., COM7, /dev/ttyACM0)")
    r.add_argument("-b", "--baud", type=int, default=1000000, help="Baud rate (default 1000000)")
    r.set_defaults(func=cmd_reset)
