from dataclasses import dataclass
from abc import ABC
from typing import List
from enum import IntEnum

from asn1.universal_types import Sequence as ASN1Sequence, ObjectIdentifier, BitString, OctetString, Enumerated
from asn1.oid import OID


class NegTokenInitReqFlag(IntEnum):
    DELEG_FLAG = 0
    MUTUAL_FLAG = 1
    REPLAY_FLAG = 2
    SEQUENCE_FLAG = 3
    ANON_FLAG = 4
    CONF_FLAG = 5
    INTEG_FLAG = 6


class NegTokenRespNegState(IntEnum):
    ACCEPT_COMPLETE = 0
    ACCEPT_INCOMPLETE = 1
    REJECT = 2
    REQUEST_MIC = 3


@dataclass
class MechType(ObjectIdentifier):
    pass


@dataclass
class MechTypeList(ASN1Sequence, ABC):
    @property
    def mech_types(self) -> List[OID]:
        return [
            MechType.from_tlv_triplet(tlv_triplet=tlv_triplet).oid
            for tlv_triplet in ASN1Sequence.from_tlv_triplet(tlv_triplet=self.elements[0]).elements
        ]


@dataclass
class ReqFlags(ASN1Sequence, ABC):
    @property
    def req_flags(self) -> NegTokenInitReqFlag:
        return NegTokenInitReqFlag(
            int.from_bytes(
                BitString.from_tlv_triplet(tlv_triplet=self.elements[0]).data,
                byteorder='big'
            )
        )


@dataclass
class MechToken(ASN1Sequence, ABC):
    @property
    def mech_token(self) -> bytes:
        return OctetString.from_tlv_triplet(tlv_triplet=self.elements[0]).data


@dataclass
class MechListMic(ASN1Sequence, ABC):
    @property
    def mech_list_mic(self) -> bytes:
        return OctetString.from_tlv_triplet(tlv_triplet=self.elements[0]).data


@dataclass
class ResponseToken(ASN1Sequence, ABC):
    @property
    def response_token(self) -> bytes:
        return OctetString.from_tlv_triplet(tlv_triplet=self.elements[0]).data


@dataclass
class SupportedMech(ASN1Sequence, ABC):
    @property
    def supported_mech(self) -> OID:
        return MechType.from_tlv_triplet(tlv_triplet=self.elements[0]).oid


@dataclass
class NegState(ASN1Sequence, ABC):
    @property
    def neg_state(self) -> NegTokenRespNegState:
        return NegTokenRespNegState(Enumerated.from_tlv_triplet(tlv_triplet=self.elements[0]).int_value)