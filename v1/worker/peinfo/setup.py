from setuptools import setup, find_packages

setup(
    name="peinfo",
    version="0.10",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Gather relevant information about an executable using pefile",
    packages=find_packages(),
    package_data={'peinfo': ['templates/*.tpl', 'peinfo.stoq', 'userdb.txt']},
    include_package_data=True,
)
