from setuptools import setup, find_packages

setup(
    name="entropy",
    version="3.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Calculate shannon entropy of a payload",
    packages=find_packages(),
    include_package_data=True,
    test_suite='tests',
)
