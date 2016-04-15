from setuptools import setup, find_packages

setup(
    name="mongodb",
    version="0.9.2",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Sends and retrieves content from MongoDB ",
    packages=find_packages(),
    include_package_data=True,
)
