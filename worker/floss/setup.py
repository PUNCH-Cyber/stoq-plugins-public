from setuptools import setup, find_packages

setup(
    name="floss",
    version="0.1",
    author="Adam Trask (@taskr)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Process a file with Fireeye Flare-FlOSS",
    packages=find_packages(),
    include_package_data=True,
)
