from setuptools import setup, find_packages

setup(
    name="threatgrid",
    version="0.0.1",
    author="Rusty Bower (@rustybower)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Interact with ThreatGrid API",
    packages=find_packages(),
    include_package_data=True,
    package_data={'threatgrid': ['threatgrid.stoq']},
)
