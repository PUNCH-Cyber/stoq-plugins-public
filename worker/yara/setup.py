from setuptools import setup, find_packages

setup(
    name="yara",
    version="0.9.3",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Process a payload using yara",
    packages=find_packages(),
    include_package_data=True,
    package_data={'yara': ['rules/*.yar', 'yarascan.stoq', 'templates/*.tpl']},
)
