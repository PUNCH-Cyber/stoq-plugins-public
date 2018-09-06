from setuptools import setup, find_packages

setup(
    name="java_class",
    version="0.1",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Decodes and extracts information from Java Class files",
    packages=find_packages(),
    include_package_data=True,
)
