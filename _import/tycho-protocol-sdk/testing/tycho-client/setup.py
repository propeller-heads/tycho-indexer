from setuptools import setup, find_packages
import sys
import platform
from pathlib import Path


def read_requirements():
    with open("requirements.txt") as req:
        content = req.read()
        requirements = content.split("\n")
    return [req for req in requirements if req and not req.startswith("#")]


# Determine the correct wheel file based on the platform and Python version
def get_wheel_file():
    path = Path(__file__).parent
    if sys.platform.startswith("darwin") and platform.machine() == "arm64":
        return str(
            path / "wheels" / f"protosim_py-0.4.9-cp39-cp39-macosx_11_0_arm64.whl"
        )
    elif sys.platform.startswith("linux") and platform.machine() == "x86_64":
        return str(
            path
            / "wheels"
            / f"protosim_py-0.4.9-cp39-cp39-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
        )
    else:
        raise RuntimeError("Unsupported platform or architecture")


wheel_file = get_wheel_file()

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
        f"protosim_py @ file://{wheel_file}",
    ],
    package_data={"tycho-client": ["../wheels/*", "./assets/*", "./bins/*"]},
    include_package_data=True,
)
