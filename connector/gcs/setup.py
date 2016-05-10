from setuptools import setup, find_packages

setup(
    name="gcs",
    version="0.1",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Sends and retrieves content from Google Cloud Storage buckets",
    packages=find_packages(),
    include_package_data=True,
)
