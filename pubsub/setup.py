from setuptools import setup, find_packages

setup(
    name="pubsub",
    version="2.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Interact with Google Cloud Pub/Sub",
    packages=find_packages(),
    include_package_data=True,
)

