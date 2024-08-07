import unittest

from coinaddrvalidator.interfaces import (
    INamedSubclassContainer, IValidator, IValidationRequest, IValidationResult
    )
from coinaddrvalidator.validation import (
    Validators, ValidatorBase, ValidationRequest, ValidationResult,
    Base58CheckValidator, EthereumValidator, validate
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
    
    def test_wrong_network_bytes_input(self):
        try:
            validate("bt", b"12nMGd6bzC8UpyWjd9HeZESZheZ8arttAb")
        except TypeError:
            assert False

    def test_wrong_network_str_input(self):
        try:
            validate("bt", "12nMGd6bzC8UpyWjd9HeZESZheZ8arttAb")
        except TypeError:
            assert False

    def test_invalid_as_default(self):
        result = validate("BTC", b"not_an_address", default_valid=False)
        self.assertFalse(result.valid)

    def test_valid_as_default(self):
        result = validate("FTM", "0x12341")
        self.assertTrue(result.valid)

    def test_uppercase_symbol(self):
        result = validate("BTC", "12nMGd6bzC8UpyWjd9HeZESZheZ8arttAb", default_valid=False)
        self.assertTrue(result.valid)

if __name__ == '__main__':
    unittest.main()
