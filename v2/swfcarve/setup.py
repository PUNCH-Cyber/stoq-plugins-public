from setuptools import setup, find_packages

setup(
    name="swfcarve",
    version="2.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Carve and decompress SWF files from a data stream",
    packages=find_packages(),
    include_package_data=True,
    install_requires=['pylzma>=0.5.0'],
    package_data={'swfcarve': ['*.stoq']},
)
