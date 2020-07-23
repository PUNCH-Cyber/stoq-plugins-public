from setuptools import setup, find_packages

setup(
    name="Azure_Sentinel_API",
    version="3.0.0",
    author="Joe Stahl (@happy-jo)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Save results and archive payloads with Azure Blob Storage",
    packages=find_packages(),
    include_package_data=True,
)