from setuptools import setup, find_packages

setup(
    name="fireeye",
    version="0.1.2",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Saves a file into a directory fireeye monitors via CIFS for analysis",
    packages=find_packages(),
    include_package_data=True,
)
