from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List, ClassVar

from spnego.negotiation_tokens.base import SPNEGONegotiationToken, register_spnego_class
from spnego.token_attributes import MechListMic, ResponseToken, SupportedMech, NegTokenRespNegState, NegState, MechType

from asn1.universal_types import Sequence as ASN1Sequence, Enumerated, OctetString
from asn1.tag_length_value_triplet import Tag, TagLengthValueTriplet
from asn1.oid import OID


@dataclass
@register_spnego_class
class NegTokenResp(SPNEGONegotiationToken):
    neg_state: Optional[NegTokenRespNegState] = None
    supported_mech: Optional[OID] = None
    response_token: Optional[bytes] = None
    mech_list_mic: Optional[bytes] = None

    spnego_tag: ClassVar[Tag] = Tag.from_bytes(data=b'\xa1')

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

    @property
    def _inner_sequence(self) -> ASN1Sequence:

        inner_elements: List[TagLengthValueTriplet] = []

        if self.neg_state is not None:
            inner_elements.append(
                self._NegState(
                    elements=(Enumerated(int_value=self.neg_state.value).tlv_triplet(),)
                ).tlv_triplet()
            )

        if self.supported_mech is not None:
            inner_elements.append(
                self._SupportedMech(
                    elements=(MechType(oid=self.supported_mech).tlv_triplet(),),
                ).tlv_triplet()
            )

        if self.response_token is not None:
            inner_elements.append(
                self._ResponseToken(
                    elements=(OctetString(data=self.response_token).tlv_triplet(),)
                ).tlv_triplet()
            )

        if self.mech_list_mic is not None:
            inner_elements.append(
                self._MechListMic(
                    elements=(OctetString(data=self.mech_list_mic).tlv_triplet(),)
                ).tlv_triplet()
            )

        return ASN1Sequence(elements=tuple(inner_elements))
