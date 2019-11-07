from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, Type, Dict, Iterable, Set, Optional, Any
from abc import ABC, abstractmethod
from inspect import getmembers, isclass

from spnego.token_attributes import TokenAttribute
from spnego.exceptions import OutOfOrderNegotiationTokenElementError, InvalidAttributeTagError, \
    MultipleAttributeError, InvalidGSSTokenTagError, InvalidNumberOfGSSTokenElementsError, \
    MissingRequiredAttributesError, NegotiationTokenTagMismatchError, NegotiationTokenOidMismatchError

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
        sequence = ASN1Sequence._from_tlv_triplet(tlv_triplet=tlv_triplet)

        if len(sequence.elements) != 2:
            raise InvalidNumberOfGSSTokenElementsError(num_observed_elements=len(sequence.elements))

        if sequence.elements[0].tag != ASN1UniversalTag.OBJECT_IDENTIFIER.value:
            raise InvalidGSSTokenTagError(observed_tag=sequence.elements[0].tag)

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
        """
        Instantiate a negotiate token from a TLV triplet.

        This method is called via the `ASN1Type.from_tlv_triplet` method. If it is called with this class, i.e.
        `SPNEGONegotiationToken.from_tlv_triplet`, this method will instantiate a negotiation token of the appropriate
        class by looking up the class with the provided TLV triplet's tag. If it is called with a child class, e.g.
        `NegTokenInit.from_tlv_triplet`, the appropriate class is chosen via the `cls` argument.

        If the method is called with a child class, a check is made to assure that the provided TLV triplet is of the
        correct format by comparing the TLV triplets tag with the chosen `cls` class' `spnego_tag`.

        The `_spnego_tag_to_class` dict is populated via a class decorator that registers the corresponding class'
        tag and class as key and value.

        :param tlv_triplet: A TLV triplet corresponding to a negotiation token.
        :return: An instance of the negotiate token class corresponding to the TLV triplet's tag.
        """

        # Import the negotiate token classes to enable the population of the `_spnego_tag_to_class` dict.
        from spnego.negotiation_tokens.neg_token_init import NegTokenInit
        from spnego.negotiation_tokens.neg_token_resp import NegTokenResp

        # Verify that the GSS token part is conformant.

        gss_token_sequence: ASN1Sequence = super()._from_tlv_triplet(tlv_triplet=tlv_triplet)
        observed_mechanism_oid: OID = ObjectIdentifier.from_tlv_triplet(tlv_triplet=gss_token_sequence.elements[0]).oid

        if observed_mechanism_oid != cls.mechanism_oid:
            raise NegotiationTokenOidMismatchError(observed_oid=observed_mechanism_oid)

        # Instantiate a negotiation token instance.

        negotiation_token_tlv_triplet: TagLengthValueTriplet = gss_token_sequence.elements[1]
        inner_sequence = ASN1Sequence.from_tlv_triplet(
            tlv_triplet=TagLengthValueTriplet.from_bytes(data=negotiation_token_tlv_triplet.value)
        )

        if cls != SPNEGONegotiationToken:
            if cls.spnego_tag != negotiation_token_tlv_triplet.tag:
                raise NegotiationTokenTagMismatchError(observed_tag=negotiation_token_tlv_triplet.tag)
            return cls._parse_attribute_elements(token_inner_elements=inner_sequence.elements)
        else:
            return cls._spnego_tag_to_class[negotiation_token_tlv_triplet.tag]._parse_attribute_elements(
                token_inner_elements=inner_sequence.elements
            )

    @classmethod
    def _parse_attribute_elements(cls, token_inner_elements: Iterable[TagLengthValueTriplet]):
        """
        Instantiate a negotiate token class from a collection of attribute elements (TLV triplets).

        :param token_inner_elements: The elements (TLV triplets) of a negotiate token's ASN.1 Sequence that
            constitute the negotiate token's attributes.
        :return: An instance of the negotiate token class corresponding to the cls argument.
        """

        if cls == SPNEGONegotiationToken:
            raise ValueError(f'The calling class must be a child class.')

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


def register_spnego_class(cls: Type[SPNEGONegotiationToken]) -> Type[SPNEGONegotiationToken]:
    cls._spnego_tag_to_class[cls.spnego_tag] = cls
    return cls
