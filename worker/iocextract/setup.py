from setuptools import setup, find_packages

setup(
    name="iocextract",
    version="0.11.1",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Utilizes reader/iocregex plugin to extract indicators of compromise from documents",
    packages=find_packages(),
    package_data={'iocextract': ['templates/*.tpl', 'iocextract.stoq']},
    include_package_data=True,
)
