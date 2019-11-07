from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Type, Dict, Iterable, Set, Optional, Any
from abc import ABC, abstractmethod
from inspect import getmembers, isclass

from spnego.token_attributes import TokenAttribute

from asn1.asn1_type import ASN1Type
from asn1.universal_types import ASN1UniversalTag,  Sequence as ASN1Sequence, ObjectIdentifier
from asn1.oid import OID
from asn1.tag_length_value_triplet import Tag, TagLengthValueTriplet


@dataclass
class GSSToken(ASN1Type, ABC):
    tag: ClassVar[Tag] = Tag.from_bytes(data=b'\x60')
    mechanism_oid: ClassVar[OID] = NotImplemented

    @property
    @abstractmethod
    def negotiation_token_tlv_triplet(self) -> TagLengthValueTriplet:
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> ASN1Sequence:
        # TODO: Add an argument to `ASN1Type`: `check_tag=True`.
        sequence = ASN1Sequence._from_tlv_triplet(tlv_triplet=tlv_triplet)

        if len(sequence.elements) != 2:
            # TODO: Use proper exception.
            raise ValueError

        if sequence.elements[0].tag != ASN1UniversalTag.OBJECT_IDENTIFIER.value:
            # TODO: Use proper exception.
            raise ValueError

        return sequence

    def tlv_triplet(self) -> TagLengthValueTriplet:
        return ASN1Sequence(
            elements=(ObjectIdentifier(oid=self.mechanism_oid).tlv_triplet(), self.negotiation_token_tlv_triplet,)
        ).tlv_triplet()


@dataclass
class SPNEGONegotiationToken(GSSToken, ABC):
    mechanism_oid: ClassVar[OID] = OID.from_string('1.3.6.1.5.5.2')
    spnego_tag: ClassVar[Tag] = NotImplemented
    _spnego_tag_to_class: ClassVar[Dict[Tag, Type[SPNEGONegotiationToken]]] = {}

    @property
    @abstractmethod
    def _inner_sequence(self) -> ASN1Sequence:
        raise NotImplementedError

    def negotiation_token_tlv_triplet(self) -> TagLengthValueTriplet:
        return TagLengthValueTriplet(tag=self.spnego_tag, value=bytes(self._inner_sequence))

    @classmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet):

        from spnego.negotiation_tokens.neg_token_init import NegTokenInit
        from spnego.negotiation_tokens.neg_token_resp import NegTokenResp

        gss_token_sequence: ASN1Sequence = super()._from_tlv_triplet(tlv_triplet=tlv_triplet)

        if ObjectIdentifier.from_tlv_triplet(tlv_triplet=gss_token_sequence.elements[0]).oid != cls.mechanism_oid:
            # TODO: Use proper exception.
            raise ValueError

        negotiation_token_tlv_triplet: TagLengthValueTriplet = gss_token_sequence.elements[1]
        inner_sequence = ASN1Sequence.from_tlv_triplet(
            tlv_triplet=TagLengthValueTriplet.from_bytes(data=negotiation_token_tlv_triplet.value)
        )

        if cls != SPNEGONegotiationToken:
            if cls.spnego_tag != negotiation_token_tlv_triplet.tag:
                # TODO: Use proper exception.
                raise ValueError
            return cls._parse_attribute_elements(token_inner_elements=inner_sequence.elements)
        else:
            return cls._spnego_tag_to_class[negotiation_token_tlv_triplet.tag]._parse_attribute_elements(
                token_inner_elements=inner_sequence.elements
            )

    @classmethod
    def _parse_attribute_elements(cls, token_inner_elements: Iterable[TagLengthValueTriplet]):

        tag_to_attribute_class: Dict[Tag, Type[TokenAttribute]] = {
            attribute_class.tag: attribute_class
            for _, attribute_class in getmembers(
                cls,
                lambda value: isclass(value) and issubclass(value, TokenAttribute)
            )
        }

        required_tags: Set[Tag] = {
            attribute_class.tag
            for attribute_class in tag_to_attribute_class.values()
            if attribute_class.required
        }

        tag_to_parsed_value: Dict[Tag, Any] = {}

        previous_tag: Optional[Tag] = None
        for element in token_inner_elements:
            # Check whether the tag is a valid attribute tag.
            if element.tag not in tag_to_attribute_class:
                # TODO: Use proper exception.
                raise ValueError
            # Check whether the tag has been observed previously (i.e. there are multiple with the same tag).
            if element.tag in tag_to_parsed_value:
                # TODO: Use proper exception.
                raise ValueError
            # Check if the tags are in the right order (i.e. have increasing tag values)
            if previous_tag is not None and element.tag <= previous_tag:
                # TODO: Use proper exception.
                raise ValueError

            tag_to_parsed_value[element.tag] = tag_to_attribute_class[element.tag].from_tlv_triplet(
                tlv_triplet=element
            ).parsed_value

            previous_tag = element.tag

        # Check if all required attributes (tags) are present.
        if any(required_tag not in tag_to_parsed_value for required_tag in required_tags):
            # TODO: Use proper exception.
            raise ValueError

        return cls(**{
            tag_to_attribute_class[tag].property_name: parsed_value
            for tag, parsed_value in tag_to_parsed_value.items()
        })


# TODO: Make a general function that generates these?
def register_spnego_class(cls: Type[SPNEGONegotiationToken]) -> Type[SPNEGONegotiationToken]:
    cls._spnego_tag_to_class[cls.spnego_tag] = cls
    return cls
