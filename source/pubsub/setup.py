from setuptools import setup, find_packages

setup(
    name="pubsub",
    version="0.3.1",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Publish and Consume messages from Google's Pub/Sub Service",
    packages=find_packages(),
    include_package_data=True,
)
