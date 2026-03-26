import pytest
from src.algorithms.fips205.parameters import get_params

def test_parameters_sizes():
    expected_sizes = {
        "SLH-DSA-SHAKE-128s": (32, 64, 7856),
        "SLH-DSA-SHAKE-128f": (32, 64, 17088),
        "SLH-DSA-SHAKE-192s": (48, 96, 16224),
        "SLH-DSA-SHAKE-192f": (48, 96, 35664),
        "SLH-DSA-SHAKE-256s": (64, 128, 29792),
        "SLH-DSA-SHAKE-256f": (64, 128, 49856),
    }

    for name, expected in expected_sizes.items():
        params = get_params(name)
        assert params.pk_bytes == expected[0], f"{name} pk_bytes mismatch"
        assert params.sk_bytes == expected[1], f"{name} sk_bytes mismatch"
        assert params.sig_bytes == expected[2], f"{name} sig_bytes mismatch"
