from setuptools import setup, find_packages

setup(
    name="trid",
    version="2.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Identify file types from their TrID signatur",
    packages=find_packages(),
    include_package_data=True,
    package_data={'trid': ['*.stoq']},
)
