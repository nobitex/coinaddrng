import unittest

from coinaddrvalidator.interfaces import (
    INamedSubclassContainer, IValidator, IValidationRequest, IValidationResult
    )
from coinaddrvalidator.validation import (
    Validators, ValidatorBase, ValidationRequest, ValidationResult,
    Base58CheckValidator, EthereumValidator
    )


class TestValidation(unittest.TestCase):
    def test_interfaces(self):
        self.assertTrue(INamedSubclassContainer.providedBy(Validators))

        validators = [Base58CheckValidator, EthereumValidator]
        for validator in validators:
            with self.subTest(validator=validator):
                self.assertTrue(IValidator.implementedBy(validator))

        self.assertTrue(
            IValidationRequest.implementedBy(ValidationRequest))
        self.assertTrue(
            IValidationResult.implementedBy(ValidationResult))

    def test_invalid_as_default(self):
        result = validate("BTC", b"not_an_address")
        self.assertFalse(result.valid)

if __name__ == '__main__':
    unittest.main()
