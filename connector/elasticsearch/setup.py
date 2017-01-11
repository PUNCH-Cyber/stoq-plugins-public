from setuptools import setup, find_packages

setup(
    name="elasticsearch",
    version="0.6",
    author="Marcus LaFerrera (@mlaferrera) Aaron Gee-Clough (@gclef_)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Saves content to an ElasticSearch index",
    packages=find_packages(),
    include_package_data=True,
)
