#include<iostream>
using namespace std;

int main()
{
    string text;
    int key;

    cin>>text;
    cin>>key;

    for(int i=0;i<text.size();i++)
    {
        if(text[i]>='A' && text[i]<='Z')
        {
            text[i]=((text[i]-'A'- key)%26)+'A';
        }

        else if(text[i]>='a' && text[i]<='z')
        {
            text[i]=((text[i]-'a'-key)%26)+'a';
        }
    }

    cout<<text;
}