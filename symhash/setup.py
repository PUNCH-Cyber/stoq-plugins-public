from setuptools import setup, find_packages

setup(
    name="symhash",
    version="3.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public/v2",
    license="Apache License 2.0",
    description="Calculate symbol table hashes of a Mach-O executable file",
    packages=find_packages(),
    include_package_data=True,
)
