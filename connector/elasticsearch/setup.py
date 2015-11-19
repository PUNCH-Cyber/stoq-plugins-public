from setuptools import setup, find_packages

setup(
    name="elasticsearch",
    version="0.2",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Saves content to an ElasticSearch index",
    packages=find_packages(),
    include_package_data=True,
)
