from setuptools import setup, find_packages

setup(
    name="ssdeep",
    version="2.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Generate a ssdeep hash of payload",
    packages=find_packages(exclude=['tests']),
    include_package_data=True,
    test_suite='tests',
)
