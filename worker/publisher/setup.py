from setuptools import setup, find_packages

setup(
    name="publisher",
    version="0.9.2",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Publish messages to single or multiple RabbitMQ queues for processing",
    packages=find_packages(),
    include_package_data=True,
)
