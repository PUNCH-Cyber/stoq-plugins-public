from setuptools import setup, find_packages

setup(
    name="hash",
    version="3.0.0",
    author="Wesley Shields <wxs@atarininja.org>, Marcus LaFerrera <@mlaferrera>",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Hash content",
    packages=find_packages(),
    include_package_data=True,
    test_suite='tests',
)
