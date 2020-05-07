from setuptools import setup, find_packages

setup(
    name="mongodb",
    version="3.0.1",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Save results and archive payloads using MongoDB",
    packages=find_packages(),
    include_package_data=True,
)
