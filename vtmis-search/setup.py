from setuptools import setup, find_packages

setup(
    name="vtmis-search",
    version="2.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Search VTMIS for sha1 hash of a payload or from results of `iocextract` plugin",
    packages=find_packages(),
    include_package_data=True,
)