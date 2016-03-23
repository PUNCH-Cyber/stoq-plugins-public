from setuptools import setup, find_packages

setup(
    name="iocregex",
    version="0.9.2",
    author="Mike Geide, Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Regex routines to extract and normalize IOC's from a payload",
    packages=find_packages(),
    include_package_data=True,
)
