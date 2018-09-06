from setuptools import setup, find_packages

setup(
    name="basicworker",
    version="0.1",
    author="Adam Trask (@Taskr)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Retrieve public feed data from Hybrid Analysis",
    packages=find_packages(),
    include_package_data=True,
)