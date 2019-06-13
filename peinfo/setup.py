from setuptools import setup, find_packages

setup(
    name="peinfo",
    version="2.1.1",
    author="Facebook, Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Gather relevant information about an executable using pefile",
    packages=find_packages(),
    include_package_data=True,
)
