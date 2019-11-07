from typing import Iterable, Set

from asn1.tag_length_value_triplet import Tag
from asn1.oid import OID


class MalformedGSSToken(Exception):
    pass


class InvalidGSSTokenTagError(MalformedGSSToken):
    def __init__(self, observed_tag: Tag):
        super().__init__(f'The tag {observed_tag} is not the correct GSSToken tag.')
        self.observed_tag: Tag = observed_tag


class InvalidNumberOfGSSTokenElementsError(MalformedGSSToken):
    def __init__(self, num_observed_elements: int):
        super().__init__(
            f'The GSSToken sequence does not the correct number of elements. Observed {num_observed_elements}.'
         )
        self.num_observed_elements: int = num_observed_elements


class MalformedNegotiationTokenError(MalformedGSSToken):
    pass


class InvalidAttributeTagError(MalformedNegotiationTokenError):
    def __init__(self, invalid_attribute_tag: Tag):
        super().__init__(f'The tag {invalid_attribute_tag}. is not a valid attribute tag.')
        self.invalid_attribute_tag: Tag = invalid_attribute_tag


class MultipleAttributeError(MalformedNegotiationTokenError):
    def __init__(self, attribute_tag: Tag):
        super().__init__(f'The attribute corresponding to tag {attribute_tag} is present multiple times.')
        self.attribute_tag: Tag = attribute_tag


class OutOfOrderNegotiationTokenElementError(MalformedNegotiationTokenError):
    def __init__(self, attribute_tag: Tag):
        super().__init__(f'The attribute corresponding to tag {attribute_tag} is not in the correct order.')
        self.attribute_tag: Tag = attribute_tag


class MissingRequiredAttributesError(MalformedNegotiationTokenError):
    def __init__(self, observed_tags: Iterable[Tag], required_tags: Iterable[Tag]):
        super().__init__(
            f'Not all required tags were observed. '
            f'Observed tags: {observed_tags}. '
            f'Required tags: {required_tags}.'
        )
        self.observed_tags: Set[Tag] = set(observed_tags)
        self.required_tags: Set[Tag] = set(required_tags)


class NegotiationTokenTagMismatchError(MalformedNegotiationTokenError):
    def __init__(self, observed_tag: Tag):
        super().__init__(
            f"The provided tag's value ({observed_tag}) does not match the requested negotiation token's tag's value."
        )
        self.observed_tag: Tag = observed_tag


class NegotiationTokenOidMismatchError(MalformedNegotiationTokenError):
    def __init__(self, observed_oid: OID):
        super().__init__(
            f"The provided GSS token's OID value ({observed_oid}) does not match the SPNEGO mechanism OID."
        )
