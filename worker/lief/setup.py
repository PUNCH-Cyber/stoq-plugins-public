from setuptools import setup, find_packages

setup(
    name="lief",
    version="0.1",
    author="Duarte Silva (@serializingme)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Parse and abstract PE, ELF and MachO files using LIEF",
    packages=find_packages(),
    include_package_data=True,
)
