from setuptools import setup, find_packages

setup(
    name="file",
    version="0.9.7",
    author="Marcus LaFerrera (@mlaferrera) & Adam Trask (@taskr)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Retrieves and saves content to local disk",
    packages=find_packages(),
    include_package_data=True,
)
