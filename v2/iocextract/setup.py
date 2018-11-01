from setuptools import setup, find_packages

setup(
    name="iocextract",
    version="2.0.0",
    author="Mike Geide, Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Regex routines to extract and normalize IOC's from a payload",
    packages=find_packages(),
    include_package_data=True,
    install_requires=['requests>=2.20.0'],
    package_data={'iocextract': ['*.stoq']},
)
