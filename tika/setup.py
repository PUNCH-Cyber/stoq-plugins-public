from setuptools import setup, find_packages

setup(
    name="tika",
    version="2.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Upload content to a Tika server for automated text extraction",
    packages=find_packages(),
    include_package_data=True,
)
