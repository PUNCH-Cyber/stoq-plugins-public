from setuptools import setup, find_packages

setup(
    name="xorsearch",
    version="2.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Scan a payload using xorsearch",
    packages=find_packages(),
    include_package_data=True,
    test_suite='tests',
)
