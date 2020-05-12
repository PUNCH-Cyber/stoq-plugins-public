from setuptools import setup, find_packages

setup(
    name="xordecode",
    version="3.0.0",
    author="Marcus LaFerrera <@mlaferrera>",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Decode XOR encoded content",
    packages=find_packages(exclude=['tests']),
    include_package_data=True,
    test_suite='tests',
    tests_require=['asynctest>=0.13.0'],
)
