from enum import Enum


class frametype(Enum):
    RECV_REQ = bytearray([0x01, 0x48])
    RECV_RESP = bytearray([0x01, 0x49])
    CMD_REQ = bytearray([0x0B, 0x0F])
    CMD_RESP = bytearray([0x0B, 0x10])
    PING_REQ = bytearray([0x0B, 0x00])
    PING_RESP = bytearray([0x0B, 0x01])
    ENUM_START_REQ = bytearray([0x00, 0x14])
    ENUM_START_RESP = bytearray([0x00, 0x15])
    ENUM_REQ = bytearray([0x00, 0x38])
    ENUM_RESP = bytearray([0x00, 0x39])
    ASSIGN_ID_REQ = bytearray([0x00, 0x3C])
    ASSIGN_ID_RESP = bytearray([0x00, 0x3D])
    IDENTIFY_REQ = bytearray([0x00, 0x3A])
    IDENTIFY_RESP = bytearray([0x00, 0x3B])
    UNKNOWN_REQ = bytearray([0x00, 0x10])
    UNKNOWN_RESP = bytearray([0x00, 0x11])
    VERSION_REQ = bytearray([0x00, 0x0A])
    VERSION_RESP = bytearray([0x00, 0x0B])
    ENUM_END_REQ = bytearray([0x0E, 0x02])
    ENUM_END_RESP = bytearray([0x00, 0x06])


class cmdtype(Enum):
    NODE_TABLE = bytearray([0x0, 0x27])


class pvtype(Enum):
    POWER_REPORT = 0x31
    TOPOLOGY_REPORT = 0x9
