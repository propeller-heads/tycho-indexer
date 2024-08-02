from setuptools import setup, find_packages


def read_requirements():
    with open("requirements.txt") as req:
        content = req.read()
        requirements = content.split("\n")
    return [req for req in requirements if req and not req.startswith("#")]


setup(
    name="tycho-client",
    version="0.1.0",
    author="Propeller Heads",
    description="A package for interacting with the Tycho API.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires="~=3.9",
    install_requires=[
        "requests==2.32.2",
        "eth-abi==2.2.0",
        "eth-typing==2.3.0",
        "eth-utils==1.9.5",
        "hexbytes==0.3.1",
        "pydantic==2.8.2",
        "protosim_py==0.4.11",
    ],
    package_data={"tycho-client": ["../wheels/*", "./assets/*", "./bins/*"]},
    include_package_data=True,
)
