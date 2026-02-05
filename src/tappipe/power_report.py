import struct
from .enums import pvtype
import logging
from .stringhex import stringhex

_LOGGER = logging.getLogger(__name__)


class power_report:
    parent = None
    bytes = []
    decoded = {}

    def __init__(self, parent=None, bytes=[]):
        self.parent = parent
        self.bytes = bytes
        self.decoded = {
            "packet_type": None,
            "nodeid": None,
            "shortaddress": None,
            "dsn": None,
            "data_length": None,
            "vin": None,
            "vout": None,
            "duty": None,
            "current": None,
            "temp": None,
            "slot": None,
            "rssi": None,
        }

        # ReceivedPacketHeader: 1 byte packet_type + 2 bytes node_address + 2 bytes short_address + 1 byte dsn + 1 byte data_length
        # PowerReport data: 13 bytes (3 voltage + 1 duty + 3 current/temp + 3 unknown + 2 slot + 1 rssi)
        # Minimum: 7 (header) + 13 (data) = 20 bytes
        if len(self.bytes) < 20:
            _LOGGER.debug(
                "Power Report: Not enough bytes, got %d, expected at least 20",
                len(self.bytes),
            )
            return

        # Parse ReceivedPacketHeader
        self.decoded["packet_type"] = self.bytes[0]
        if self.decoded["packet_type"] != pvtype.POWER_REPORT.value:
            _LOGGER.warning(
                "Power Report: Wrong packet type 0x%02x, expected 0x31",
                self.decoded["packet_type"],
            )
            return

        (self.decoded["nodeid"], self.decoded["shortaddress"]) = struct.unpack(
            ">HH", self.bytes[1:5]
        )
        self.decoded["dsn"] = self.bytes[5]
        self.decoded["data_length"] = self.bytes[6]

        # Parse PowerReport data (starts at byte 7)
        data_start = 7

        # U12Pair: voltage_in_and_voltage_out (3 bytes)
        voltage_in_raw = (self.bytes[data_start] << 4) | (
            self.bytes[data_start + 1] >> 4
        )
        voltage_out_raw = ((self.bytes[data_start + 1] & 0x0F) << 8) | self.bytes[
            data_start + 2
        ]
        self.decoded["vin"] = voltage_in_raw / 20.0  # * 0.05V
        self.decoded["vout"] = voltage_out_raw / 10.0  # * 0.1V

        # dc_dc_duty_cycle (1 byte)
        self.decoded["duty"] = self.bytes[data_start + 3] / 255.0

        # U12Pair: current_and_temperature (3 bytes)
        current_raw = (self.bytes[data_start + 4] << 4) | (
            self.bytes[data_start + 5] >> 4
        )
        temp_raw = ((self.bytes[data_start + 5] & 0x0F) << 8) | self.bytes[
            data_start + 6
        ]
        self.decoded["current"] = current_raw / 200.0  # * 0.005A

        # Temperature with sign extension for negative values
        if temp_raw & 0x800:
            temp_raw = temp_raw | 0xF000  # Two's complement
        temp_signed = temp_raw if temp_raw < 0x8000 else temp_raw - 0x10000
        self.decoded["temp"] = temp_signed / 10.0  # * 0.1°C

        # unknown (3 bytes) - skip bytes 10-12
        # slot_counter (2 bytes)
        (self.decoded["slot"],) = struct.unpack(
            ">H", self.bytes[data_start + 10 : data_start + 12]
        )

        # rssi (1 byte)
        self.decoded["rssi"] = self.bytes[data_start + 12]

        _LOGGER.info(
            "Power Report - Node: 0x%04x, Slot: %d, Vin: %.2fV, Vout: %.2fV, Current: %.3fA, Temp: %.1f°C, Duty: %.1f%%, RSSI: %d",
            self.decoded["nodeid"],
            self.decoded["slot"],
            self.decoded["vin"],
            self.decoded["vout"],
            self.decoded["current"],
            self.decoded["temp"],
            self.decoded["duty"] * 100,
            self.decoded["rssi"],
        )
        _LOGGER.debug("Power Report decoded: %s", self.decoded)
        _LOGGER.debug("Power Report bytes: %s", stringhex(self.bytes))

    def setDebug(self, debug):
        self.debug = debug

    def setLogLevel(self, logLevel):
        self.loglevel = logLevel

    def getType(self):
        return pvtype.POWER_REPORT.value
