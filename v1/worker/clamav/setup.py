from setuptools import setup, find_packages

setup(
    name="clamav",
    version="0.3",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Scan content with ClamAV",
    packages=find_packages(),
    include_package_data=True,
)
