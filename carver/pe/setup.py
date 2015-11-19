from setuptools import setup, find_packages

setup(
    name="pe",
    version="0.9",
    author="Jeff Ito, Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Carve portable executable files from a data stream",
    packages=find_packages(),
    include_package_data=True,
)
