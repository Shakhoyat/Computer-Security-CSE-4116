#include<iostream>
#include<string>
using namespace std;

int main()
{
    string text, key, cipher;

    cout<<"Enter Plain Text: ";
    cin>>text;

    cout<<"Enter Key: ";
    cin>>key;

    if(text.length()!=key.length())
    {
        cout<<"Key length must be same as plaintext.";
        return 0;
    }

    // Encryption
    for(int i=0; i<text.length(); i++)
    {
        cipher = cipher + char(text[i] ^ key[i]);
    }

    cout<<"\nEncrypted (ASCII): ";

    for(int i=0; i<cipher.length(); i++)
    {
        cout<<(int)cipher[i]<<" ";
    }

    cout<<"\n\nDecrypted Text: ";

    // Decryption
    for(int i=0; i<cipher.length(); i++)
    {
        cout<<char(cipher[i] ^ key[i]);
    }

    return 0;
}