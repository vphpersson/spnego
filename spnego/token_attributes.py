from dataclasses import dataclass
from typing import List, Any, Optional, Dict, Iterable, ClassVar, Type, Set
from enum import IntEnum
from abc import ABC, abstractmethod

from asn1.universal_types import Sequence as ASN1Sequence, ObjectIdentifier, BitString, OctetString, Enumerated
from asn1.oid import OID
from asn1.tag_length_value_triplet import Tag, TagLengthValueTriplet


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
    required: ClassVar[bool] = False

    @property
    @abstractmethod
    def parsed_value(self) -> Any:
        raise NotImplementedError

    @property
    def property_name(self) -> str:
        return 


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


def parse_attribute_elements(
    token_inner_elements: Iterable[TagLengthValueTriplet],
    attribute_classes: Iterable[Type[TokenAttribute]]
) -> Dict[str, Any]:

    valid_tag_to_attribute_class: Dict[Tag, Type[TokenAttribute]] = {
        attribute_class.tag: attribute_class
        for attribute_class in attribute_classes
    }
    required_tags: Set[Tag] = {attribute_class.tag for attribute_class in attribute_classes}

    tag_to_parsed_value: Dict[Tag, Any] = {}

    previous_tag: Optional[Tag] = None
    for element in token_inner_elements:
        # Check if the tag is not a valid attribute tag.
        if element.tag not in valid_tag_to_attribute_class:
            # TODO: Use proper exception.
            raise ValueError
        # Check if the tag has been observed previously (i.e. there are multiple with the same tag).
        if element.tag in tag_to_parsed_value:
            # TODO: Use proper exception.
            raise ValueError
        # Check if the tags are in the right order (i.e. have increasing tag values)
        if previous_tag is not None and element.tag <= previous_tag:
            # TODO: Use proper exception.
            raise ValueError

        tag_to_parsed_value[element.tag] = valid_tag_to_attribute_class[element.tag].from_tlv_triplet(
            tlv_triplet=element
        ).parsed_value

        previous_tag = element.tag

    # Check if all required attributes (tags) are present.
    if any(required_tag not in tag_to_parsed_value for required_tag in required_tags):
        # TODO: Use proper exception.
        raise ValueError

    return {
        valid_tag_to_attribute_class[tag]: parsed_value
        for tag, parsed_value in tag_to_parsed_value
    }
