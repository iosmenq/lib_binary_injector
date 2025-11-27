# INSTALL GCC AND BUILD CODE
sudo apt install build-essential && gcc -shared -fPIC -o libbinaryinject.so main.c -ldl

# MAKE TEST BINARY
gcc test_binary.c -o test
