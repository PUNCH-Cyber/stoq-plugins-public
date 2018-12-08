from setuptools import setup, find_packages

setup(
    name="s3",
    version="2.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Read and write data to Amazon S3",
    packages=find_packages(),
    include_package_data=True,
)

