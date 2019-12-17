from setuptools import setup, find_packages

setup(
    name="exif",
    version="2.0.2",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Processes a payload using ExifTool",
    packages=find_packages(exclude=['tests']),
    include_package_data=True,
    test_suite='tests',
)
