from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List, ClassVar

from spnego.negotiation_tokens import ASN1AttributeParserMixin
from spnego.token_attributes import MechListMic, ResponseToken, SupportedMech, NegTokenRespNegState, NegState, MechType

from asn1.asn1_type import ASN1Type
from asn1.universal_types import Enumerated, OctetString, Sequence as ASN1Sequence
from asn1.tag_length_value_triplet import Tag, TagLengthValueTriplet
from asn1.oid import OID


@dataclass
class NegTokenResp(ASN1Type, ASN1AttributeParserMixin):
    neg_state: Optional[NegTokenRespNegState] = None
    supported_mech: Optional[OID] = None
    response_token: Optional[bytes] = None
    mech_list_mic: Optional[bytes] = None

    spnego_tag: ClassVar[Tag] = Tag.from_bytes(data=b'\xa1')
    tag: ClassVar[Tag] = spnego_tag

    class _NegState(NegState):
        tag = Tag.from_bytes(data=b'\xa0')
        property_name = 'neg_state'

    class _SupportedMech(SupportedMech):
        tag = Tag.from_bytes(data=b'\xa1')
        property_name = 'supported_mech'

    class _ResponseToken(ResponseToken):
        tag = Tag.from_bytes(data=b'\xa2')
        property_name = 'response_token'

    class _MechListMic(MechListMic):
        tag = Tag.from_bytes(data=b'\xa3')
        property_name = 'mech_list_mic'

    @classmethod
    def _from_tlv_triplet(cls, tlv_triplet: TagLengthValueTriplet) -> NegTokenResp:
        return cls._parse_attribute_elements(
            token_inner_elements=ASN1Sequence.from_bytes(data=tlv_triplet.value).elements
        )

    def tlv_triplet(self) -> TagLengthValueTriplet:

        elements: List[TagLengthValueTriplet] = []

        if self.neg_state is not None:
            elements.append(
                self._NegState(
                    elements=(Enumerated(int_value=self.neg_state.value).tlv_triplet(),)
                ).tlv_triplet()
            )

        if self.supported_mech is not None:
            elements.append(
                self._SupportedMech(
                    elements=(MechType(oid=self.supported_mech).tlv_triplet(),),
                ).tlv_triplet()
            )

        if self.response_token is not None:
            elements.append(
                self._ResponseToken(
                    elements=(OctetString(data=self.response_token).tlv_triplet(),)
                ).tlv_triplet()
            )

        if self.mech_list_mic is not None:
            elements.append(
                self._MechListMic(
                    elements=(OctetString(data=self.mech_list_mic).tlv_triplet(),)
                ).tlv_triplet()
            )

        return TagLengthValueTriplet(
            tag=self.tag,
            value=bytes(ASN1Sequence(elements=tuple(elements)))
        )

