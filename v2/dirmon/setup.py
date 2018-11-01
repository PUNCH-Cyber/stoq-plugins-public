from setuptools import setup, find_packages

setup(
    name="dirmon",
    version="2.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Monitor a directory for newly created files for processing",
    packages=find_packages(),
    include_package_data=True,
    install_requires=['watchdog>=0.9.0'],
    package_data={'dirmon': ['*.stoq']},
)
