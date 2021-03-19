from setuptools import setup, find_packages

setup(
    name="azure_blob",
    version="3.0.0",
    author="Kiran Pradhan (@kiranpradhan01)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Save results and archive payloads with Azure Blob Storage",
    packages=find_packages(),
    include_package_data=True,
)