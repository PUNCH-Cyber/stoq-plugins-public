from setuptools import setup, find_packages

setup(
    name="xyz",
    version="3.0.0",
    author="Marcus LaFerrera <@mlaferrera>",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0, MIT",
    description="Extract Zip file metadata",
    packages=find_packages(),
    include_package_data=True,
)
