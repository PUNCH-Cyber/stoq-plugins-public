from setuptools import setup, find_packages

setup(
    name="opswat",
    version="0.9.2",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Submit content to an OPSWAT Metascan server for scanning and retrieve the results",
    packages=find_packages(),
    include_package_data=True,
)

