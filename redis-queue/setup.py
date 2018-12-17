from setuptools import setup, find_packages

setup(
    name="redis-queue",
    version="2.0.1",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Interact with Redis server for queuing",
    packages=find_packages(),
    include_package_data=True,
)

