from setuptools import setup, find_packages

setup(
    name="bitrot",
    version="0.3",
    author="Adam Trask, Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Rotate bits left or right. Defaults to 4 bits right for nibble swapping.",
    packages=find_packages(),
    include_package_data=True,
)
