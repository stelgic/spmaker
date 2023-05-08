# BUILD DEPENDENCY LIBRARIES WIN-64


#### Install OneTBB
```
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh #.\bootstrap-vcpkg.bat(for Windows)
./vcpkg integrate install
./vcpkg install tbb
```

#### Install Openssl
```
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh
./vcpkg integrate install
vcpkg install openssl:x64-windows
```

#### Install Boost
```
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh
./vcpkg integrate install
vcpkg install boost:x64-windows-static
```

#### Install Libwebsockets
```
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh
./vcpkg integrate install
vcpkg install libwebsockets
```

#### Install JSONCPP
```
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh
./vcpkg integrate install
./vcpkg install jsoncpp
```

#### Build G3LOG
```
git clone https://github.com/KjellKod/g3log
cd g3log
mkdir build && cd build

cmake .. -G "Visual Studio 16 2019" -DG3_SHARED_LIB=OFF -DCMAKE_INSTALL_PREFIX=D:/LIBRARIES/g3log -DADD_G3LOG_UNIT_TEST=ON -DADD_FATAL_EXAMPLE=OFF
```

#### Build CPR
```
git clone https://github.com/whoshuu/cpr.git
cd cpr
git submodule update --init --recursive
git checkout 1.4.0
mkdir build && cd build

cmake .. -G "Visual Studio 16 2019" -DCPR_USE_SYSTEM_CURL=On -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=D:/LIBRARIES/cpr -DOPENSSL_ROOT="D:/OPENSOURCES/vcpkg/installed/x64-windows" -DBUILD_CPR_TESTS=OFF
```
