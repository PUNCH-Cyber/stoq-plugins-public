from setuptools import setup, find_packages

setup(
    name="stdout",
    version="0.9",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Sends content to STDOUT",
    packages=find_packages(),
    include_package_data=True,
)

