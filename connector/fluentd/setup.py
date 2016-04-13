from setuptools import setup, find_packages

setup(
    name="fluentd",
    version="0.2",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Sends content to a fluentd server",
    packages=find_packages(),
    include_package_data=True,
)
