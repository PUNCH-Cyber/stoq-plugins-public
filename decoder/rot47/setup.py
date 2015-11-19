from setuptools import setup, find_packages

setup(
    name="rot47",
    version="0.1",
    author="Adam Trask (@taskr)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Decode ROT47 encoded content",
    packages=find_packages(),
    include_package_data=True,
)
