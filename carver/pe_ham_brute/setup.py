from setuptools import setup, find_packages

setup(
    name="pe_ham_brute",
    version="0.1",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Search for n-grams for use as XOR key and leverages hamming distance to determine key size.",
    packages=find_packages(),
    include_package_data=True,
)
