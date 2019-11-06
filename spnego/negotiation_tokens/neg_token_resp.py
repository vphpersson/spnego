from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, List
from contextlib import suppress

from spnego.negotiation_tokens.base import SPNEGONegotiationToken
from spnego.token_attributes import MechListMic, ResponseToken, SupportedMech, NegTokenRespNegState, NegState, MechType

from asn1.universal_types import Sequence as ASN1Sequence, Enumerated, OctetString
from asn1.tag_length_value_triplet import Tag, TagLengthValueTriplet
from asn1.oid import OID


@dataclass
class NegTokenResp(SPNEGONegotiationToken):
    neg_state: Optional[NegTokenRespNegState] = None
    supported_mech: Optional[OID] = None
    response_token: Optional[bytes] = None
    mech_list_mic: Optional[bytes] = None

    class _NegState(NegState):
        tag = Tag.from_bytes(data=b'\xa0')

    class _SupportedMech(SupportedMech):
        tag = Tag.from_bytes(data=b'\xa1')

    class _ResponseToken(ResponseToken):
        tag = Tag.from_bytes(data=b'\xa2')

    class _MechListMic(MechListMic):
        tag = Tag.from_bytes(data=b'\xa3')

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

    @classmethod
    def _from_inner_sequence(cls, inner_sequence: ASN1Sequence) -> NegTokenResp:




        pass
