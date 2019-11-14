from setuptools import setup, find_packages

setup(
    name="xdpcarve",
    version="3.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Carve and decode elements from XDP objects",
    packages=find_packages(),
    include_package_data=True,
)
