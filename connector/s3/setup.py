from setuptools import setup, find_packages

setup(
    name="s3",
    version="0.3",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Sends and retrieves content from Amazon S3 buckets",
    packages=find_packages(),
    include_package_data=True,
)
