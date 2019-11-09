from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, List, Optional

from spnego.negotiation_tokens.base import GSSToken, ASN1AttributeParserMixin
from spnego.token_attributes import MechTypeList, ReqFlags, MechToken, MechListMic, NegTokenInitReqFlag

from asn1.universal_types import Sequence as ASN1Sequence, SequenceOf, OctetString, ObjectIdentifier, BitString
from asn1.tag_length_value_triplet import Tag, TagLengthValueTriplet
from asn1.oid import OID


@dataclass
class NegTokenInit(GSSToken, ASN1AttributeParserMixin):
    mech_types: List[OID]
    req_flags: Optional[NegTokenInitReqFlag] = None
    mech_token: Optional[bytes] = None
    mech_list_mic: Optional[bytes] = None

    mechanism_oid: ClassVar[OID] = OID.from_string('1.3.6.1.5.5.2')
    spnego_tag: ClassVar[Tag] = Tag.from_bytes(data=b'\xa0')

    class _MechTypeList(MechTypeList):
        tag = Tag.from_bytes(data=b'\xa0')
        property_name = 'mech_types'
        required = True

    class _ReqFlags(ReqFlags):
        tag = Tag.from_bytes(data=b'\xa1')
        property_name = 'req_flags'

    class _MechToken(MechToken):
        tag = Tag.from_bytes(data=b'\xa2')
        property_name = 'mech_token'

    class _MechListMic(MechListMic):
        tag = Tag.from_bytes(data=b'\xa3')
        property_name = 'mech_list_mic'

    @classmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> NegTokenInit:
        negotiate_token_sequence: ASN1Sequence = cls.extract_negotiate_token_sequence(gss_token_tlv_triplet=tlv_triplet)
        return cls._parse_attribute_elements(token_inner_elements=negotiate_token_sequence.elements)

    @property
    def negotiation_token_tlv_triplet(self) -> TagLengthValueTriplet:

        inner_elements: List[TagLengthValueTriplet] = [
            self._MechTypeList(
                elements=(
                    SequenceOf(
                        elements=tuple(ObjectIdentifier(oid=oid).tlv_triplet() for oid in self.mech_types)
                    ).tlv_triplet(),
                )
            ).tlv_triplet()
        ]

        if self.req_flags is not None:
            inner_elements.append(
                self._ReqFlags(elements=(BitString(data=bytes([self.req_flags.value])).tlv_triplet(),)).tlv_triplet()
            )

        if self.mech_token is not None:
            inner_elements.append(
                self._MechToken(elements=(OctetString(data=self.mech_token).tlv_triplet(),)).tlv_triplet()
            )

        if self.mech_list_mic is not None:
            inner_elements.append(
                self._MechListMic(elements=(OctetString(data=self.mech_list_mic).tlv_triplet(),)).tlv_triplet()
            )

        return ASN1Sequence(elements=tuple(inner_elements)).tlv_triplet()

