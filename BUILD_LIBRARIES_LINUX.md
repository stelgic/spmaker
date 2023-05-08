# BUILD DEPENDENCY LIBRARIES LINUX


#### C++17
```
sudo yum install devtoolset-9-toolchain
```

#### UUID LIBDEVEL
```
sudo yum install libuuid-devel
```

#### BUILD OneTBB
```
git clone https://github.com/oneapi-src/oneTBB.git

cd oneTBB

mkdir build && cd build

cmake -DCMAKE_INSTALL_PREFIX=/usr/local/onetbb -DTBB_TEST=OFF ..

cmake --build .

cmake --install .
```

#### BUILD G3LOG
```
git clone https://github.com/KjellKod/g3log

cd g3log

mkdir build && cd build

cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local/g3log -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release

sudo make install
```

#### BUILD OPENSSL
```
sudo wget https://www.openssl.org/source/openssl-1.1.1g.tar.gz

sudo tar -xf openssl-1.1.1g.tar.gz

cd openssl-1.1.1g

sudo ./config --prefix=/usr/local/openssl-1.1.1g --openssldir=/usr/local/openssl-1.1.1g shared zlib

make

sudo make install

sudo ln -sf /usr/local/openssl-1.1.1g /usr/local/openssl
```

#### BUILD BOOST
```
wget https://boostorg.jfrog.io/artifactory/main/release/1.73.0/source/boost_1_73_0.tar.gz

tar -xzf boost_1_73_0.tar.gz

cd boost_1_73_0

./bootstrap.sh --prefix=/usr/local/boost_1_73_0

sudo ./b2 install --prefix=/usr/local/boost_1_73_0 --without-python

sudo ln -sf /usr/local/boost_1_73_0 /usr/local/boost
```

#### LIBWEBSOCKETS
```
git clone https://github.com/warmcat/libwebsockets.git

cd libwebsockets

git checkout v4.1.0-rc2

mkdir build && cd build

cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local/libwebsockets -DLWS_WITH_HTTP2=1 -DLWS_OPENSSL_INCLUDE_DIRS=/usr/local/openssl-1.1.1c/include -DLWS_OPENSSL_LIBRARIES="/usr/local/openssl-1.1.1c/lib/libssl.so;/usr/local/openssl-1.1.1c/lib/libcrypto.so"

make

sudo make install

sudo ln -sf /usr/local/libwebsockets-4.1.0 /usr/local/libwebsockets
```

#### BUILD CURL
```
wget https://curl.haxx.se/download/curl-7.68.0.tar.gz

gunzip -c curl-7.68.0.tar.gz | tar xvf -

cd curl-7.68.0

./configure --with-ssl=/usr/local/openssl-1.1.1c --prefix=/usr/local/curl-7.68.0

make 

sudo make install

sudo ln -sf /usr/local/curl-7.68.0 /usr/local/curl
```

#### BUILD CPR
```
git clone https://github.com/whoshuu/cpr.git

cd cpr

git submodule update --init --recursive

git checkout 1.4.0

mkdir build && cd build

cmake -DCMAKE_INSTALL_PREFIX=/usr/local/cpr-1.4.0 -DCURL_INCLUDE_DIRS="/usr/local/curl-7.68.0/include;/usr/local/curl-7.68.0/include/curl" -DCURL_LIBRARIES="libcurl.so" -DBUILD_SHARED_LIBS=ON  ..

make 

sudo make install

sudo ln -sf /usr/local/cpr-1.4.0 /usr/local/cpr
```





