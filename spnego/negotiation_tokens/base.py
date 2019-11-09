from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Type, Dict, Iterable, Set, Optional, Any, List
from abc import ABC, abstractmethod
from inspect import getmembers, isclass

from spnego.token_attributes import TokenAttribute
from spnego.exceptions import OutOfOrderNegotiationTokenElementError, InvalidAttributeTagError, \
    MultipleAttributeError, InvalidGSSTokenTagError, InvalidNumberOfGSSTokenElementsError, \
    MissingRequiredAttributesError, NegotiationTokenOidMismatchError

from asn1.asn1_type import ASN1Type
from asn1.universal_types import ASN1UniversalTag,  Sequence as ASN1Sequence, ObjectIdentifier
from asn1.oid import OID
from asn1.tag_length_value_triplet import Tag, TagLengthValueTriplet
from asn1.utils import extract_elements


@dataclass
class GSSToken(ASN1Type, ABC):
    tag: ClassVar[Tag] = Tag.from_bytes(data=b'\x60')
    mechanism_oid: ClassVar[OID] = NotImplemented

    @property
    @abstractmethod
    def negotiation_token_tlv_triplet(self) -> TagLengthValueTriplet:
        raise NotImplementedError

    @classmethod
    def extract_negotiate_token_sequence(cls, gss_token_tlv_triplet: TagLengthValueTriplet) -> ASN1Sequence:
        gss_token_elements: List[TagLengthValueTriplet] = extract_elements(elements_data=gss_token_tlv_triplet.value)

        if len(gss_token_elements) != 2:
            raise InvalidNumberOfGSSTokenElementsError(num_observed_elements=len(gss_token_elements))

        if gss_token_elements[0].tag != ASN1UniversalTag.OBJECT_IDENTIFIER.value:
            raise InvalidGSSTokenTagError(observed_tag=gss_token_elements[0].tag)

        observed_mechanism_oid: OID = ObjectIdentifier.from_tlv_triplet(tlv_triplet=gss_token_elements[0]).oid
        if observed_mechanism_oid != cls.mechanism_oid:
            raise NegotiationTokenOidMismatchError(observed_oid=observed_mechanism_oid)

        return ASN1Sequence.from_bytes(data=gss_token_elements[1].value)

    def tlv_triplet(self) -> TagLengthValueTriplet:
        return TagLengthValueTriplet(
            tag=self.tag,
            value=bytes(ObjectIdentifier(oid=self.mechanism_oid)) + bytes(self.negotiation_token_tlv_triplet)
        )


class ASN1AttributeParserMixin:

    # TODO: How should i type hint `cls` and the return value?
    @classmethod
    def _parse_attribute_elements(cls, token_inner_elements: Iterable[TagLengthValueTriplet]):
        """
        Instantiate a ASN.1 Sequence-like class from a collection of attribute elements (TLV triplets).

        :param token_inner_elements: The elements (TLV triplets) that constitute the instance's attributes.
        :return: An instance of the negotiate token class corresponding to the cls argument.
        """

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
                raise InvalidAttributeTagError(invalid_attribute_tag=element.tag)
            # Check whether the tag has been observed previously (i.e. there are multiple with the same tag).
            if element.tag in tag_to_parsed_value:
                raise MultipleAttributeError(attribute_tag=element.tag)
            # Check if the tags are in the right order (i.e. have increasing tag values)
            if previous_tag is not None and element.tag <= previous_tag:
                raise OutOfOrderNegotiationTokenElementError(attribute_tag=element.tag)

            tag_to_parsed_value[element.tag] = tag_to_attribute_class[element.tag].from_tlv_triplet(
                tlv_triplet=element
            ).parsed_value

            previous_tag = element.tag

        # Check if all required attributes (tags) are present.
        if any(required_tag not in tag_to_parsed_value for required_tag in required_tags):
            raise MissingRequiredAttributesError(observed_tags=tag_to_parsed_value.keys(), required_tags=required_tags)

        # Build the negotiation arguments, and build the corresponding class.
        return cls(**{
            tag_to_attribute_class[tag].property_name: parsed_value
            for tag, parsed_value in tag_to_parsed_value.items()
        })
