from setuptools import setup

setup(
    name="truelayer-signing",
    version="0.1.0",
    packages=['truelayer_signing', ],
    long_description=open('README.md').read(),
    setup_requires=["wheel", "pytest-runner"],
    install_requires=["pyjwt[crypto]"],
    tests_require=['pytest'],
    python_requires=">=3.9"
)
