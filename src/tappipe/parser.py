from .frame import frame
from .stringhex import stringhex
import logging

_LOGGER = logging.getLogger(__name__)


class parser:
    bytes = []
    startFrame = bytearray([0xFF, 0x7E, 0x07])
    endFrame = bytearray([0x7E, 0x08])

    def __init__(self, bytes=[]):
        self.bytes = bytearray(bytes)

    def __add__(self, other):
        self.bytes += other
        return self

    def setDebug(self, debug):
        self.debug = debug

    def setLogLevel(self, logLevel):
        self.loglevel = logLevel

    def fetchFrame(self):
        frameStarted = self.bytes.find(self.startFrame)
        if frameStarted > -1:
            _LOGGER.debug("Frame Start Pattern found at %d", frameStarted)
        else:
            _LOGGER.debug("Frame Start Pattern not found")
        frameEnded = self.bytes.find(self.endFrame, frameStarted)
        if frameEnded > -1:
            _LOGGER.debug("Frame End Pattern found at %d", frameEnded)
        else:
            _LOGGER.debug("Frame End Pattern not found")
        if frameStarted > -1 and frameEnded > -1:
            fr = frame(self.bytes[frameStarted : frameEnded + len(self.endFrame)])
            self.bytes = self.bytes[frameEnded + len(self.endFrame) :]
            _LOGGER.debug("Frame found with bytes %s", stringhex(fr.bytes))
            if fr.failedCRC:
                _LOGGER.debug("Frame CRC Failed")
            else:
                _LOGGER.debug("Frame CRC Passed")
                return fr
        return False
