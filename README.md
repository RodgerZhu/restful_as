# restful_as

g++ -m64 -O2 -DSGX_TRUSTED -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type -Waddress -Wsequence-point -Wformat-security -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls -Wnon-virtual-dtor -std=c++11 -fPIC -Wno-attributes -IApp -DNDEBUG -UEDEBUG -UDEBUG -DQVL_ONLY -DSGX_QPL_LOGGING=1 -c App/App.cpp -o App/App.o
echo "CXX  <=  App/App.cpp"

g++ App/App.o -o app -L/opt/alibaba/teesdk/intel/sgxsdk/lib64 -lsgx_dcap_quoteverify -lpthread -ldl -ldcap_quoteprov  -I ./include -lpthread -lssl -lcrypto
![Uploading image.png…]()
