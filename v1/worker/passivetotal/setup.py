from setuptools import setup, find_packages

setup(
    name="passivetotal",
    version="0.9",
    author="Marcus LaFerrera (@mlaferrera)",
    url="https://github.com/PUNCH-Cyber/stoq-plugins-public",
    license="Apache License 2.0",
    description="Interact with PassiveTotal API",
    packages=find_packages(),
    package_data={'passivetotal': ['passivetotal.stoq', 'templates/*.tpl']},
    include_package_data=True,
)
