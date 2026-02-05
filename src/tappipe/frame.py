import struct
from .crc import crc
from .enums import frametype
from .recv_resp import recv_resp
from .cmd_resp import cmd_resp
import logging
from .stringhex import stringhex

_LOGGER = logging.getLogger(__name__)


class frame:
    bytes = []
    failedCRC = False
    decoded = {}
    escapeItems = [
        ([0x7E, 0x0], [0x7E]),
        ([0x7E, 0x1], [0x24]),
        ([0x7E, 0x2], [0x23]),
        ([0x7E, 0x3], [0x25]),
        ([0x7E, 0x4], [0xA4]),
        ([0x7E, 0x5], [0xA3]),
        ([0x7E, 0x6], [0xA5]),
    ]
    processor = None

    def __init__(self, bytes=[]):
        self.bytes = bytearray(bytes)
        self.decoded = {"address": None, "type": None}
        self.processor = None

        # Remove start frame marker (0xFF 0x7E 0x07 or 0x7E 0x07)
        if len(self.bytes) >= 3 and self.bytes[0:3] == bytearray([0xFF, 0x7E, 0x07]):
            self.bytes = self.bytes[3:]
        elif len(self.bytes) >= 2 and self.bytes[0:2] == bytearray([0x7E, 0x07]):
            self.bytes = self.bytes[2:]

        # Remove end frame marker (0x7E 0x08)
        if len(self.bytes) >= 2 and self.bytes[-2:] == bytearray([0x7E, 0x08]):
            self.bytes = self.bytes[:-2]

        # Now apply escape sequences to the frame body
        self.escape()

        # Minimum frame: 2 bytes address + 2 bytes type + 2 bytes CRC = 6 bytes
        if len(self.bytes) < 6:
            _LOGGER.debug("Frame too short: %d bytes", len(self.bytes))
            return

        # Check CRC (covers address + type + payload, last 2 bytes are CRC)
        if self.checkCRC() == False:
            _LOGGER.debug("CRC Failed")
            return

        # Parse address and type from the frame
        keys = ["address", "type"]
        values = struct.unpack(">2s2s", self.bytes[0:4])
        self.decoded = dict(zip(keys, values))
        # Data is everything between type and CRC
        self.decoded["data"] = bytearray(self.bytes[4:-2])

    def setDebug(self, debug):
        self.debug = debug

    def setLogLevel(self, logLevel):
        self.loglevel = logLevel

    def checkCRC(self):
        _LOGGER.debug("Frame Bytes %s", stringhex(self.bytes))
        # CRC is the last 2 bytes, in big-endian format
        crc_val = (self.bytes[-2] << 8) + self.bytes[-1]
        try:
            # CRC covers everything except the last 2 bytes (the CRC itself)
            test = crc(self.bytes[:-2])
            crc_result = test.check()
            _LOGGER.debug("CRC From Frame is %04x, Expected %04x", crc_result, crc_val)
        except Exception as e:
            _LOGGER.error("Fehler bei CRC: %s", e)
            self.failedCRC = True
            return False
        if crc_result == crc_val:
            _LOGGER.debug("CRC PASSED")
            self.failedCRC = False
            return True
        else:
            _LOGGER.debug("CRC FAILED")
            self.failedCRC = True
            return False

    def escape(self):
        for y in self.escapeItems:
            self.bytes = self.bytes.replace(bytearray(y[0]), bytearray(y[1]))
        _LOGGER.debug("Escaped Frame Bytes %s", stringhex(self.bytes))

    def getAddress(self):
        return self.decoded["address"]

    def getType(self):
        return self.decoded["type"]

    def process(self):
        t = self.getType()
        if t == frametype.RECV_REQ.value:
            _LOGGER.info("Frame Type is RECV_REQ")
        elif t == frametype.RECV_RESP.value:
            _LOGGER.info("Frame Type is RECV_RESP")
            self.processor = recv_resp(self, self.decoded["data"])
        elif t == frametype.CMD_REQ.value:
            _LOGGER.info("Frame Type is CMD_REQ")
        elif t == frametype.CMD_RESP.value:
            _LOGGER.info("Frame Type is CMD_RESP")
            self.processor = cmd_resp(self, self.decoded["data"])
        elif t == frametype.PING_REQ.value:
            _LOGGER.info("Frame Type is PING_REQ")
        elif t == frametype.PING_RESP.value:
            _LOGGER.info("Frame Type is PING_RESP")
        elif t == frametype.ENUM_START_REQ.value:
            _LOGGER.info("Frame Type is ENUM_START_REQ")
        elif t == frametype.ENUM_START_RESP.value:
            _LOGGER.info("Frame Type is ENUM_START_RESP")
        elif t == frametype.ENUM_REQ.value:
            _LOGGER.info("Frame Type is ENUM_REQ")
        elif t == frametype.ENUM_RESP.value:
            _LOGGER.info("Frame Type is ENUM_RESP")
        elif t == frametype.ASSIGN_ID_REQ.value:
            _LOGGER.info("Frame Type is ASSIGN_ID_REQ")
        elif t == frametype.ASSIGN_ID_RESP.value:
            _LOGGER.info("Frame Type is ASSIGN_ID_RESP")
        elif t == frametype.IDENTIFY_REQ.value:
            _LOGGER.info("Frame Type is IDENTIFY_REQ")
        elif t == frametype.IDENTIFY_RESP.value:
            _LOGGER.info("Frame Type is IDENTIFY_RESP")
        elif t == frametype.UNKNOWN_REQ.value:
            _LOGGER.info("Frame Type is UNKNOWN_REQ")
        elif t == frametype.UNKNOWN_RESP.value:
            _LOGGER.info("Frame Type is UNKNOWN_RESP")
        elif t == frametype.VERSION_REQ.value:
            _LOGGER.info("Frame Type is VERSION_REQ")
        elif t == frametype.VERSION_RESP.value:
            _LOGGER.info("Frame Type is VERSION_RESP")
        elif t == frametype.ENUM_END_REQ.value:
            _LOGGER.info("Frame Type is ENUM_END_REQ")
        elif t == frametype.ENUM_END_RESP.value:
            _LOGGER.info("Frame Type is ENUM_END_RESP")
        else:
            _LOGGER.info(f"Unknown frame type: {t!r}")
            self.processor = None
