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
#openssl
wget https://www.openssl.org/source/openssl-1.1.1v.tar.gz
./config --prefix=${PROJECT_INSTALL_DIR}
make
make install

#protobuf
wget https://github.com/protocolbuffers/protobuf/archive/v21.9.zip
unzip v21.9.zip -d .
cd protobuf-21.9
mkdir build
cd build
cmake .. \
  -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -Dprotobuf_BUILD_TESTS=OFF \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -Dprotobuf_BUILD_SHARED_LIBS=ON -DCMAKE_CXX_FLAGS="-fPIC" \
   -DCMAKE_INSTALL_PREFIX=${PROJECT_INSTALL_DIR}
make
make install

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

#rapidjson
wget https://github.com/Tencent/rapidjson/archive/v1.1.0.tar.gz
tar -xzf v1.1.0.tar.gz
cd rapidjson-1.1.0
mkdir build
cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DRAPIDJSON_BUILD_EXAMPLES=OFF \
  -DRAPIDJSON_BUILD_TESTS=OFF \
  -DRAPIDJSON_BUILD_DOC=OFF \
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
export OPENSSL_CUSTOM_ROOT_DIR=/home/phi/openacs/sample-project/tcl_modules
cmake .. \
  -DTINK_BUILD_SHARED_LIB=ON \
  -DTINK_USE_INSTALLED_ABSEIL=ON \
  -DTINK_USE_SYSTEM_OPENSSL=ON \
  -DTINK_USE_INSTALLED_PROTOBUF=ON \
  -DTINK_USE_INSTALLED_RAPIDJSON=ON \
  -DCMAKE_SKIP_RPATH=ON \
  -DCMAKE_BUILD_TYPE=Release \
   -DCMAKE_INSTALL_PREFIX=${PROJECT_INSTALL_DIR}

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