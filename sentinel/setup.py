from setuptools import setup, find_packages

setup(
    name="sentinel",
    version="3.0.0",
    author="Joe Stahl (@happy-jo)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Send reults to Azure Sentinel (Log Analytics Workspace) using the Azure Log Analytics API",
    packages=find_packages(),
    include_package_data=True,
)
