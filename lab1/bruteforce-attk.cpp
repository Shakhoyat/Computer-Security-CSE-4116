#include<iostream>
using namespace std;

int main()
{
    string cipher;

    cin>>cipher;

    for(int key=0;key<26;key++)
    {
        cout<<"Key "<<key<<" : ";

        for(int i=0;i<cipher.size();i++)
        {
            char ch=((cipher[i]-'A'-key+26)%26)+'A';
            cout<<ch;
        }

        cout<<endl;
    }

    return 0;
}