from setuptools import setup, find_packages

setup(
    name="basicworker",
    version="0.1.1",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="stoQ framework example of a basic worker plugin",
    packages=find_packages(),
    include_package_data=True,
)

