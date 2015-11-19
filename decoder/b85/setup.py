from setuptools import setup, find_packages

setup(
    name="b85",
    version="0.1",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Decode base85 encoded content",
    packages=find_packages(),
    include_package_data=True,
)

