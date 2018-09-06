from setuptools import setup, find_packages

setup(
    name="domainiq",
    version="0.2",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Interact with DomainIQ API",
    packages=find_packages(),
    include_package_data=True,
)
