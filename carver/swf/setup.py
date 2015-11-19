from setuptools import setup, find_packages

setup(
    name="ole",
    version="0.9",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Carve and decompress SWF payloads",
    packages=find_packages(),
    include_package_data=True,
)
