from setuptools import setup, find_packages

setup(
    name="rtf",
    version="2.0.0",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Extract objects from RTF payloads",
    packages=find_packages(),
    include_package_data=True,
    install_requires=['oletools>=0.53.1'],
    package_data={'rtf': ['*.stoq']},
)
