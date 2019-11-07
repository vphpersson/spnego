from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, List, Optional

from spnego.negotiation_tokens.base import SPNEGONegotiationToken, register_spnego_class
from spnego.token_attributes import MechTypeList, ReqFlags, MechToken, MechListMic, NegTokenInitReqFlag

from asn1.universal_types import Sequence as ASN1Sequence, OctetString, ObjectIdentifier, BitString
from asn1.tag_length_value_triplet import Tag, TagLengthValueTriplet
from asn1.oid import OID


@dataclass
@register_spnego_class
class NegTokenInit(SPNEGONegotiationToken):
    mech_types: List[OID]
    req_flags: Optional[NegTokenInitReqFlag] = None
    mech_token: Optional[bytes] = None
    mech_list_mic: Optional[bytes] = None

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

    @property
    def _inner_sequence(self) -> ASN1Sequence:

        inner_elements: List[TagLengthValueTriplet] = [
            self._MechTypeList(
                elements=(
                    ASN1Sequence(
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

        return ASN1Sequence(elements=tuple(inner_elements))

