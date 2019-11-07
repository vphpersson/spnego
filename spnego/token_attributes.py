"""
Attributes of negotiate tokens.

Each attribute class is abstract, because an attribute class' `tag` value is determined by its relative position in a
token's set of attributes. Thus, to utilize the attribute classes, they must be inherited from and a `tag` value must
be added and set to its appropriate value.
"""

from dataclasses import dataclass
from typing import List, Any, ClassVar
from enum import IntEnum
from abc import ABC, abstractmethod

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
class TokenAttribute(ASN1Sequence, ABC):
    # Whether the attribute is required, i.e. must be present.
    required: ClassVar[bool] = False
    # The name of the class instance that should store the token's parsed value.
    property_name: ClassVar[str] = NotImplemented

    @property
    @abstractmethod
    def parsed_value(self) -> Any:
        raise NotImplementedError


@dataclass
class MechTypeList(TokenAttribute, ABC):
    @property
    def parsed_value(self) -> List[OID]:
        return [
            MechType.from_tlv_triplet(tlv_triplet=tlv_triplet).oid
            for tlv_triplet in ASN1Sequence.from_tlv_triplet(tlv_triplet=self.elements[0]).elements
        ]


@dataclass
class ReqFlags(TokenAttribute, ABC):
    @property
    def parsed_value(self) -> NegTokenInitReqFlag:
        return NegTokenInitReqFlag(
            int.from_bytes(
                BitString.from_tlv_triplet(tlv_triplet=self.elements[0]).data,
                byteorder='big'
            )
        )


@dataclass
class MechToken(TokenAttribute, ABC):
    @property
    def parsed_value(self) -> bytes:
        return OctetString.from_tlv_triplet(tlv_triplet=self.elements[0]).data


@dataclass
class MechListMic(TokenAttribute, ABC):
    @property
    def parsed_value(self) -> bytes:
        return OctetString.from_tlv_triplet(tlv_triplet=self.elements[0]).data


@dataclass
class ResponseToken(TokenAttribute, ABC):
    @property
    def parsed_value(self) -> bytes:
        return OctetString.from_tlv_triplet(tlv_triplet=self.elements[0]).data


@dataclass
class SupportedMech(TokenAttribute, ABC):
    @property
    def parsed_value(self) -> OID:
        return MechType.from_tlv_triplet(tlv_triplet=self.elements[0]).oid


@dataclass
class NegState(TokenAttribute, ABC):
    @property
    def parsed_value(self) -> NegTokenRespNegState:
        return NegTokenRespNegState(Enumerated.from_tlv_triplet(tlv_triplet=self.elements[0]).int_value)
