from setuptools import setup, find_packages

setup(
    name="symhash",
    version="0.2",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Generate a symhash for Mach-O binaries",
    packages=find_packages(),
    include_package_data=True,
)
