from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from abc import ABC, abstractmethod

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

    @property
    @abstractmethod
    def _inner_sequence(self) -> ASN1Sequence:
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def _from_inner_sequence(cls, inner_sequence: ASN1Sequence) -> SPNEGONegotiationToken:
        raise NotImplementedError

    def negotiation_token_tlv_triplet(self) -> TagLengthValueTriplet:
        return TagLengthValueTriplet(tag=self.spnego_tag, value=bytes(self._inner_sequence))

    @classmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet):
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
            return cls._from_inner_sequence(inner_sequence=inner_sequence)
        else:
            # TODO: Instantiate using map.
            ...
