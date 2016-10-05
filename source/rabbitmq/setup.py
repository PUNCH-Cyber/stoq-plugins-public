from setuptools import setup, find_packages

setup(
    name="rabbitmq",
    version="0.10",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Publish and Consume messages from a RabbitMQ Server",
    packages=find_packages(),
    include_package_data=True,
)
