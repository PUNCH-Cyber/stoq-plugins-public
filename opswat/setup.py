from setuptools import setup, find_packages

setup(
    name="opswat",
    version="3.0.1",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Scan payloads using OPSWAT MetaDefender",
    packages=find_packages(),
    include_package_data=True,
)
