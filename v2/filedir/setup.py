from setuptools import setup, find_packages

setup(
    name="filedir",
    version="2.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Handle file and directory interactions ",
    packages=find_packages(),
    include_package_data=True,
    package_data={'filedir': ['*.stoq']},
)
