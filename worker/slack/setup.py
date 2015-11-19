from setuptools import setup, find_packages

setup(
    name="slack",
    version="0.9",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Interact with stoQ Plugins using Slack as an interface",
    packages=find_packages(),
    include_package_data=True,
)
