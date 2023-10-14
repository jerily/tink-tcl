# tink-tcl

Tcl bindings for [Tink](https://github.com/tink-crypto/tink-cc), a multi-language, cross-platform library that provides cryptographic APIs that are secure, easy to use correctly, and hard(er) to misuse.

## Set the installation directory
```bash
export PROJECT_INSTALL_DIR=/path/to/your/project
```

## Clone the repository
```bash
git clone https://github.com/jerily/tink-tcl.git
cd tink-tcl
export TINK_TCL_DIR=`pwd`
```

## Install dependencies
```bash

#abseil
wget https://github.com/abseil/abseil-cpp/archive/refs/tags/20230125.0.tar.gz
tar -xzf 20230125.0.tar.gz
cd abseil-cpp-20230125.0
mkdir build
cd build
cmake .. \
  -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=${PROJECT_INSTALL_DIR}
make
make install

#tink
wget https://github.com/tink-crypto/tink-cc/archive/refs/tags/v2.0.0.tar.gz
tar -xzf v2.0.0.tar.gz
cd tink-cc-2.0.0
patch -p1 < ${TINK_TCL_DIR}/tink-cc-2.0.0.diff
mkdir build
cd build
cmake .. \
  -DTINK_BUILD_SHARED_LIB=ON \
  -DTINK_USE_INSTALLED_ABSEIL=ON \
  -DTINK_USE_SYSTEM_OPENSSL=OFF \
  -DTINK_USE_INSTALLED_PROTOBUF=OFF \
  -DTINK_USE_INSTALLED_RAPIDJSON=OFF \
  -DCMAKE_SKIP_RPATH=ON \
  -DCMAKE_BUILD_TYPE=Release
make
make install
```

## Install module for TCL
```bash
cd ${TINK_TCL_DIR}
mkdir build
cd build
export LD_LIBRARY_PATH=${PROJECT_INSTALL_DIR}:$LD_LIBRARY_PATH
cmake .. -DCMAKE_INSTALL_PREFIX=${PROJECT_INSTALL_DIR}
make
make install
```