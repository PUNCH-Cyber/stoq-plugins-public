from setuptools import setup, find_packages

setup(
    name="suricata-dirmon",
    version="0.8",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Monitor a directory for files extracted by Suricata",
    packages=find_packages(),
    include_package_data=True,
)
