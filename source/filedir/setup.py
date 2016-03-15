from setuptools import setup, find_packages

setup(
    name="filedir",
    version="1.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Ingest a file or directory for processing",
    packages=find_packages(),
    include_package_data=True,
)
