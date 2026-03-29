import re

with open('tests/test_algorithms.py', 'r') as f:
    text = f.read()

text = text.replace(
    '    BIKE,\n    HQC,\n    ClassicMcEliece,\n    Dilithium,\n    NTRULPRime,\n    StreamlinedNTRUPrime,\n',
    '    Dilithium,\n    ML_KEM,\n    SLH_DSA,\n'
)

# Clean up parameter sets import
text = re.sub(
    r'from src\.algorithms\.bike import PARAMETER_SETS as BIKE_PARAM_SETS\n.*?\nfrom src\.algorithms\.ntru_prime import PARAMETER_SETS as SNTRUP_PARAM_SETS',
    'from src.algorithms.dilithium import PARAMETER_SETS as DILITHIUM_PARAM_SETS\nfrom src.algorithms.fips205 import PARAMETER_SETS as SLH_DSA_PARAM_SETS',
    text,
    flags=re.DOTALL
)

with open('tests/test_algorithms.py', 'w') as f:
    f.write(text)
