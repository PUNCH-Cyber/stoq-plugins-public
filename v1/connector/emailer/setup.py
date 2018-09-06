from setuptools import setup, find_packages

setup(
    name="emailer",
    version="0.4",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Send results to recipients via e-mail",
    packages=find_packages(),
    include_package_data=True,
)
