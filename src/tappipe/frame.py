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
        self.escape()
        if len(self.bytes) < 12:
            _LOGGER.debug("Frame too short")
            return
        if self.checkCRC() == False:
            _LOGGER.debug("CRC Failed")
            return
        keys = ["address", "type"]
        values = struct.unpack(">xxx2s2s", self.bytes[0:7])
        self.decoded = dict(zip(keys, values))
        self.decoded["data"] = bytearray(self.bytes[7:-4])

    def setDebug(self, debug):
        self.debug = debug

    def setLogLevel(self, logLevel):
        self.loglevel = logLevel

    def checkCRC(self):
        _LOGGER.debug("Frame Bytes %s", stringhex(self.bytes))
        crc_val = (self.bytes[-4] << 8) + self.bytes[-3]
        try:
            test = crc(self.bytes[3:-4])
            crc_result = test.check()
            _LOGGER.debug("CRC From Frame is %04x", crc_result)
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
        match self.getType():
            case t if t == frametype.RECV_RESP.value:
                _LOGGER.debug("Frame Type is RECV_RESP")
                self.processor = recv_resp(self, self.decoded["data"])
            case t if t == frametype.CMD_RESP.value:
                _LOGGER.debug("Frame Type is CMD_RESP")
                self.processor = cmd_resp(self, self.decoded["data"])
            case t:
                _LOGGER.debug(f"Unknown frame type: {t!r}")
                self.processor = None
