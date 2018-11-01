from setuptools import setup, find_packages

setup(
    name="tnef",
    version="2.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public/v2",
    license="Apache License 2.0",
    description="TNEF File Extractor",
    packages=find_packages(),
    include_package_data=True,
    package_data={'tnef': ['*.stoq']},
)
