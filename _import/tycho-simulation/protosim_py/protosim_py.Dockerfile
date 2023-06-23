FROM quay.io/pypa/manylinux2014_x86_64

RUN curl --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:$PATH" 
RUN /opt/python/cp39-cp39/bin/python -m pip install maturin

WORKDIR /prop-builder/protosim_py
CMD /opt/python/cp39-cp39/bin/python -m maturin build --release --compatibility manylinux2014 -i /opt/python/cp39-cp39/bin/python