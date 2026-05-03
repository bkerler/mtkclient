#!/usr/bin/env python3
import argparse
import json
import socket
import struct
import sys


def build_argparser():
    parser = argparse.ArgumentParser(description="Example MTK TCP/IP client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=31337)
    subparsers = parser.add_subparsers(dest="command", required=True)

    read_parser = subparsers.add_parser("read")
    read_parser.add_argument("address")
    read_parser.add_argument("dwords", nargs="?")

    write_parser = subparsers.add_parser("write")
    write_parser.add_argument("address")
    write_group = write_parser.add_mutually_exclusive_group(required=True)
    write_group.add_argument("--data")
    write_group.add_argument("--value", nargs="+")
    return parser


class MtkTcpipClient:
    def __init__(self, host, port, verbose=False):
        self.host = host
        self.port = port
        self.verbose = verbose

    def send_request(self, request):
        with socket.create_connection((self.host, self.port)) as sock:
            if self.verbose:
                print(request)
                sys.stdout.flush()
            sock.sendall(json.dumps(request).encode("utf-8") + b"\n")
            response = b""
            while b"\n" not in response:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        if not response:
            raise RuntimeError("No response from server")
        result = json.loads(response.split(b"\n", 1)[0].decode("utf-8"))
        if result.get("status") != "ok":
            raise RuntimeError(result.get("error", "Request failed"))
        return result

    @staticmethod
    def _ensure_int(value, name):
        if not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")
        return value

    @staticmethod
    def _pack_write_values(value):
        if isinstance(value, int):
            return struct.pack("<I", value & 0xFFFFFFFF)
        if isinstance(value, (bytes, bytearray)):
            data = bytes(value)
            if len(data) % 4:
                data += b"\x00" * (4 - (len(data) % 4))
            return data
        if isinstance(value, list):
            packed = bytearray()
            for item in value:
                if not isinstance(item, int):
                    raise TypeError("write32 list items must be integers")
                packed.extend(struct.pack("<I", item & 0xFFFFFFFF))
            return bytes(packed)
        raise TypeError("write32 value must be an integer, bytes-like object, or list of integers")

    def read32(self, address: int, dwords: int = 1):
        self._ensure_int(address, "address")
        self._ensure_int(dwords, "dwords")
        if dwords <= 0:
            raise ValueError("dwords must be > 0")
        data = self.read(address=address, length=dwords * 4, registers=True)
        values = [struct.unpack("<I", data[pos:pos + 4])[0] for pos in range(0, len(data), 4)]
        if dwords == 1:
            return values[0]
        return values

    def write32(self, address: int, value):
        self._ensure_int(address, "address")
        data = self._pack_write_values(value)
        return self.write(address=address, data=data, registers=True)

    def read(self, address: int, length: int, registers: bool = True) -> bytes:
        self._ensure_int(address, "address")
        self._ensure_int(length, "length")
        if length <= 0:
            raise ValueError("length must be > 0")
        response = self.send_request({
            "action": "read",
            "address": address,
            "length": length,
            "registers": registers,
        })
        return bytes.fromhex(response["data"])

    def write(self, address: int, data, registers: bool = True):
        self._ensure_int(address, "address")
        if isinstance(data, int):
            payload = self._pack_write_values(data)
        elif isinstance(data, (bytes, bytearray, list)):
            payload = self._pack_write_values(data)
        else:
            raise TypeError("write data must be an integer, bytes-like object, or list of integers")
        self.send_request({
            "action": "write",
            "address": address,
            "data": payload.hex(),
            "registers": registers,
        })
        return True

    def readmem(self, address: int, length: int) -> bytes:
        return self.read(address=address, length=length, registers=False)

    def writemem(self, address: int, data):
        return self.write(address=address, data=data, registers=False)


def main():
    parser = build_argparser()
    args = parser.parse_args()
    mtk_tcp = MtkTcpipClient(args.host, args.port)
    address = int(args.address, 0)
    if args.command == "read":
        dwords = int(args.dwords, 0) if args.dwords is not None else 1
        print(mtk_tcp.read32(address=address, dwords=dwords))
    else:
        if args.data is not None:
            data = args.data[2:] if args.data.startswith("0x") else args.data
            value = bytes.fromhex(data)
        else:
            parsed_values = [int(item, 0) for item in args.value]
            value = parsed_values[0] if len(parsed_values) == 1 else parsed_values
        print(mtk_tcp.write32(address=address, value=value))
    return 0


if __name__ == "__main__":
    sys.exit(main())
