#include <bits/stdc++.h>
using namespace std;

int main(){
    string text,key;
    cout<<"Enter plaintext: ";
    getline(cin,text);
    cout<<"Enter key (same length): ";
    getline(cin,key);
    if(key.size()!=text.size()){cout<<"Key length must match plaintext.\n";return 0;}
    string cipher;
    for(size_t i=0;i<text.size();++i) cipher+=text[i]^key[i];
    cout<<"Cipher (hex): ";
    for(unsigned char c:cipher) printf("%02x",c);
    cout<<"\nDecrypted: ";
    for(size_t i=0;i<cipher.size();++i) cout<<(char)(cipher[i]^key[i]);
    cout<<"\n";
}
