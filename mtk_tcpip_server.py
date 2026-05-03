#!/usr/bin/env python3
import argparse
import json
import logging
import selectors
import socket
import sys
import threading
from types import SimpleNamespace

from mtk_api import connect, init


class RegisterTcpServer:
    CANONICAL_CLOCK_BASE = 0x14000000
    CANONICAL_SSR_BASE = 0x14003000
    CANONICAL_CCC_BASE = 0x14005000
    MMIO_WINDOW_SIZE = 0x1000

    def __init__(self, mtk, host="127.0.0.1", port=31337):
        self.mtk = mtk
        self.host = host
        self.port = port
        self.selector = selectors.DefaultSelector()
        self.server_socket = None
        self.running = False
        self.da_lock = threading.Lock()

    @staticmethod
    def _parse_int(value, field_name):
        if value is None:
            raise ValueError(f"Missing '{field_name}'")
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            return int(value, 0)
        raise ValueError(f"Invalid '{field_name}'")

    @staticmethod
    def _parse_bool(value, field_name):
        if isinstance(value, bool):
            return value
        if value is None:
            raise ValueError(f"Missing '{field_name}'")
        raise ValueError(f"Invalid '{field_name}'")

    @staticmethod
    def _normalize_write_data(request):
        if "data" in request:
            data = request["data"]
            if isinstance(data, list):
                return bytes(data)
            if isinstance(data, str):
                value = data.strip()
                if value.startswith("0x"):
                    hex_value = value[2:]
                    if len(hex_value) % 2:
                        hex_value = "0" + hex_value
                    return bytes.fromhex(hex_value)
                return bytes.fromhex(value)
            raise ValueError("Invalid 'data'")
        if "value" in request:
            value = RegisterTcpServer._parse_int(request["value"], "value")
            length = RegisterTcpServer._parse_int(request.get("length", 4), "length")
            return value.to_bytes(length, "little", signed=False)
        raise ValueError("Missing 'data' or 'value'")

    @staticmethod
    def _align_up(value, alignment):
        return (value + alignment - 1) & -alignment

    @staticmethod
    def _window_contains(base, address, size):
        return base is not None and base <= address < base + size

    def _translate_register_address(self, address):
        chipconfig = getattr(getattr(self.mtk, "config", None), "chipconfig", None)
        if chipconfig is None:
            return address

        clock_base = getattr(chipconfig, "ssr_clk_base", None)
        ssr_base = getattr(chipconfig, "ssr_base", None)

        if self._window_contains(self.CANONICAL_CLOCK_BASE, address, self.MMIO_WINDOW_SIZE) and clock_base is not None:
            return clock_base + (address - self.CANONICAL_CLOCK_BASE)
        if self._window_contains(self.CANONICAL_SSR_BASE, address, self.MMIO_WINDOW_SIZE) and ssr_base is not None:
            return ssr_base + 0x3000 + (address - self.CANONICAL_SSR_BASE)
        if self._window_contains(self.CANONICAL_CCC_BASE, address, self.MMIO_WINDOW_SIZE) and ssr_base is not None:
            return ssr_base + 0x5000 + (address - self.CANONICAL_CCC_BASE)
        return address

    def _peek_registers(self, addr, length):
        translated_addr = self._translate_register_address(addr)
        data = self.mtk.daloader.peek(addr=translated_addr, length=length, registers=True)
        return translated_addr, data

    def _poke_registers(self, addr, data):
        translated_addr = self._translate_register_address(addr)
        start = translated_addr & ~0x3
        end = self._align_up(translated_addr + len(data), 4)
        if start != translated_addr or len(data) % 4:
            original = bytearray(self.mtk.daloader.peek(addr=start, length=end - start, registers=True))
            offset = translated_addr - start
            original[offset:offset + len(data)] = data
            payload = bytes(original)
        else:
            payload = data

        for pos in range(0, len(payload), 4):
            value = int.from_bytes(payload[pos:pos + 4], "little", signed=False)
            self.mtk.daloader.poke(addr=start + pos, data=value, registers=True)
        return translated_addr

    def _read_data(self, request):
        addr = self._parse_int(request.get("address"), "address")
        length = self._parse_int(request.get("length", 4), "length")
        registers = self._parse_bool(request.get("registers", True), "registers")
        if length <= 0:
            raise ValueError("'length' must be > 0")
        with self.da_lock:
            if registers:
                translated_addr, data = self._peek_registers(addr=addr, length=length)
            else:
                translated_addr = addr
                data = self.mtk.daloader.peek(addr=addr, length=length, registers=False)
        response = {
            "status": "ok",
            "address": addr,
            "translated_address": translated_addr,
            "registers": registers,
            "length": length,
            "data": data.hex(),
        }
        if "length" not in request:
            response["value"] = int.from_bytes(data, "little", signed=False)
        return response

    def _write_data(self, request):
        addr = self._parse_int(request.get("address"), "address")
        data = self._normalize_write_data(request)
        registers = self._parse_bool(request.get("registers", True), "registers")
        with self.da_lock:
            if registers:
                translated_addr = self._poke_registers(addr=addr, data=data)
            else:
                translated_addr = addr
                self.mtk.daloader.poke(addr=addr, data=data, registers=False)
        return {
            "status": "ok",
            "address": addr,
            "translated_address": translated_addr,
            "registers": registers,
            "length": len(data),
            "data": data.hex(),
        }

    def _handle_request(self, request):
        if not isinstance(request, dict):
            raise ValueError("JSON request must be an object")
        action = request.get("action", "read")
        if action == "read":
            return self._read_data(request)
        if action == "write":
            return self._write_data(request)
        raise ValueError("Unsupported action")

    def _accept(self, sock):
        connection, address = sock.accept()
        connection.setblocking(False)
        state = SimpleNamespace(addr=address, inb=b"", outb=b"")
        self.selector.register(connection, selectors.EVENT_READ, data=state)

    def _service(self, key, mask):
        sock = key.fileobj
        state = key.data
        if mask & selectors.EVENT_READ:
            data = sock.recv(4096)
            if not data:
                self._close_connection(sock)
                return
            state.inb += data
            while b"\n" in state.inb:
                line, state.inb = state.inb.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    request = json.loads(line.decode("utf-8"))
                    response = self._handle_request(request)
                except Exception as err:
                    response = {"status": "error", "error": str(err)}
                state.outb += json.dumps(response).encode("utf-8") + b"\n"
            events = selectors.EVENT_READ | (selectors.EVENT_WRITE if state.outb else 0)
            self.selector.modify(sock, events, data=state)
        if mask & selectors.EVENT_WRITE and state.outb:
            sent = sock.send(state.outb)
            state.outb = state.outb[sent:]
            events = selectors.EVENT_READ | (selectors.EVENT_WRITE if state.outb else 0)
            self.selector.modify(sock, events, data=state)

    def _close_connection(self, sock):
        try:
            self.selector.unregister(sock)
        except Exception:
            pass
        sock.close()

    def serve_forever(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        self.server_socket.setblocking(False)
        self.selector.register(self.server_socket, selectors.EVENT_READ, data=None)
        self.running = True
        print(f"Listening on {self.host}:{self.port}")
        try:
            while self.running:
                for key, mask in self.selector.select(timeout=1):
                    if key.data is None:
                        self._accept(key.fileobj)
                    else:
                        self._service(key, mask)
        except KeyboardInterrupt:
            pass
        finally:
            self.close()

    def close(self):
        self.running = False
        for key in list(self.selector.get_map().values()):
            self._close_connection(key.fileobj)
        self.selector.close()


def build_argparser():
    parser = argparse.ArgumentParser(description="MTK DA TCP register server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=31337)
    parser.add_argument("--preloader")
    parser.add_argument("--loader")
    parser.add_argument("--serialport")
    parser.add_argument("--directory", default=".")
    parser.add_argument("--loglevel", default="INFO")
    return parser


def main():
    parser = build_argparser()
    args = parser.parse_args()
    loglevel = getattr(logging, str(args.loglevel).upper(), logging.INFO)
    mtk = init(
        preloader=args.preloader,
        loader=args.loader,
        serialport=args.serialport,
    )
    mtk, _da_handler = connect(mtk=mtk, directory=args.directory, loglevel=loglevel)
    if mtk is None:
        print("Failed to connect to device", file=sys.stderr)
        return 1
    server = RegisterTcpServer(mtk=mtk, host=args.host, port=args.port)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
