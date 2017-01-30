from setuptools import setup, find_packages

setup(
    name="queue",
    version="0.3.1",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Send results to a queuing system, such as RabbitMQ",
    packages=find_packages(),
    include_package_data=True,
)
