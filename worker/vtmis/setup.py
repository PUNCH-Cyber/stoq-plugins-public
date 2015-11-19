from setuptools import setup, find_packages

setup(
    name="vtmis",
    version="0.8",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Interact with VTMIS public and private API",
    packages=find_packages(),
    include_package_data=True,
)
