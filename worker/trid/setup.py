from setuptools import setup, find_packages

setup(
    name="trid",
    version="0.5",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Identify file types from their TrID signature",
    packages=find_packages(),
    package_data={'trid': ['trid.stoq', 'templates/*.tpl']},
    include_package_data=True,
)
