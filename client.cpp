#include <iostream>
#include <fstream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/osrng.h"
#include "cryptopp/hex.h"
#include <cryptopp/base64.h>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/types.h>

using namespace std;
using namespace CryptoPP;

int client_socket;

void closeSocket(int signo) {
    cout << "Closing socket..." << endl;
    close(client_socket);
    exit(signo);
}

bool createDirectory(const string& path) {
    if (mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == 0) {
        return true; // Directory created successfully
    } else {
        cerr << "Error creating directory: " << path << endl;
        return false;
    }
}

void createFile(const string& str, const string& data) {
string str2=str;
    ofstream file(str2);
   if (file.is_open()) {
        file << data;
        file.close();}
    
    else {
       cerr << "Error creating file: " << str2<< endl;
    }
}

string readFile(const string str) {
string str2=str;
    string data;
    ifstream file(str2);
    if (file.is_open()) {
        getline(file, data);
        file.close();
    }
    else {
        cerr << "Error reading file: " << str2 << endl;
    }
    return data;
}


string encryptText(const string& plainText, const string& key) {
    string cipherText;

    CryptoPP::AES::Encryption aesEncryption((byte*)key.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, (byte*)key.c_str());

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipherText));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.length() + 1);
    stfEncryptor.MessageEnd();

    string encodedText;
    CryptoPP::StringSource(cipherText, true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(encodedText),
            false  ));

    return encodedText;
}


string decryptText(const string& encodedText, const string& key) {
    string cipherText;
    CryptoPP::StringSource(encodedText, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(cipherText) ));
    string decryptedText;
    CryptoPP::AES::Decryption aesDecryption((byte*)key.c_str(), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, (byte*)key.c_str());

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedText));
    stfDecryptor.Put(reinterpret_cast<const unsigned char*>(cipherText.c_str()), cipherText.size());
    stfDecryptor.MessageEnd();

    return decryptedText;
}



void sendChoice(char choice) {
    send(client_socket, &choice, sizeof(choice), 0);
}

void sendFileName(const string& fileName) {
    send(client_socket, fileName.c_str(), fileName.size(), 0);
}


   
string receiveData() {
    char buffer[4096];
    int bytes_received = recv(client_socket, buffer, sizeof(buffer)-1, 0);
    if (bytes_received == -1) {
        cerr << "Error receiving data\n";
        return "";
    }
    //buffer[bytes_received]='\0';
    return string(buffer, bytes_received);
}

int main() {
    signal(SIGINT, closeSocket);

    // Create socket and connect to server
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        cerr << "Error creating socket\n";
        return 1;
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8085);
    inet_pton(AF_INET, "172.20.193.189", &server_address.sin_addr);

    if (connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) {
        cerr << "Error connecting to server\n";
        return 2;
    }

    cout << "Connected to server\n";

  
    string hexkey;  
    // Send choice (signup or login) to server
    string choice;
    cout << "Enter your choice (signup or login): ";
    cin >> choice;
     string username, password;

    if (send(client_socket, choice.c_str(), choice.size(), 0) == -1) {
        cerr << "Error sending choice" << endl;
        close(client_socket);
        return 1;
    }

    if (choice == "signup") {
        // Send signup data (username and password) to server
       
        cout << "Enter username: ";
        cin >> username;
        cout << "Enter password: ";
        cin >> password;

        string signupData = username + " " + password;
        if (send(client_socket, signupData.c_str(), signupData.size(), 0) == -1) {
            cerr << "Error sending signup data" << endl;
            close(client_socket);
            return 1;
        }
    }
     else if (choice == "login") {
      
        cout << "Enter username: ";
        cin >> username;
        cout << "Enter password: ";
        cin >> password;

        string loginData = username + " " + password;
        if (send(client_socket, loginData.c_str(), loginData.size(), 0) == -1) {
            cerr << "Error sending login data" << endl;
            close(client_socket);
            return 1;
        }

        // Receive login result from server
        char responseBuffer[1024];
        int responseBytesReceived = recv(client_socket, responseBuffer, sizeof(responseBuffer), 0);
        if (responseBytesReceived == -1) {
            cerr << "Error receiving login result" << endl;
            close(client_socket);
            return 1;
        }

        string loginResult(responseBuffer, responseBytesReceived);
        cout << "Server response: " << loginResult << endl;
        if(loginResult=="Login failed"){close(client_socket);return 0;}
    } 
    else {
        cerr << "Invalid choice" << endl;
    }
    
    

    // Receive menu options from server
    string menu = receiveData();
    cout << "Server menu:\n" << menu << endl;
    
    if(choice=="signup"){
     AutoSeededRandomPool prng; // Initialize a random number generator

    // Generate a random key
   byte key[AES::DEFAULT_KEYLENGTH];
    prng.GenerateBlock(key, sizeof(key));

    // Convert the key to a string
    HexEncoder encoder(new StringSink(hexkey));
    encoder.Put(key, sizeof(key));
    encoder.MessageEnd();
    //cout<<hexkey<<endl;
    createFile(username+"_key.txt",hexkey);
    }
    else if(choice=="login"){
    hexkey=readFile(username+"_key.txt");
   
    }

    // Send choice to server
    while(1){
    char choice;
    cout << "Enter choice: ";
    cin >> choice;
    sendChoice(choice);

  
 // Handle client choice
string fileName, data;
switch (choice) {
   case '1':  {// Creation
        cout << "Enter file name: ";
        cin >> fileName;
        sendFileName(fileName);
        break;}
    case '2': { // Reading
        cout << "Enter file name: ";
        cin >> fileName;
        sendFileName(fileName);
        string encryptedData = receiveData();
        cout << "Encrypted data received: " << encryptedData << endl;
        cout<<"lenght : "<<encryptedData.size()<<endl;
        // Decrypt data
      
        string decryptedData = decryptText(encryptedData, hexkey);
        cout << "Decrypted data: " << decryptedData << endl;
        break;}
        
    case '3': { // Deletion
        cout << "Enter file name: ";
        cin >> fileName;
        sendFileName(fileName);
        break;}
        
    case '4': { // Modification
        cout << "Enter file name: ";
        cin >> fileName;
        sendFileName(fileName);
        cout << "Enter new data: ";
        cin.ignore();
        getline(cin, data);
        
        // Encrypt data
         string encryptedData = encryptText(data, hexkey);
    cout<<"encrypted data sending to server is : "<<encryptedData<<endl;
    cout<<"length : "<<encryptedData.size()<<endl;
    send(client_socket, encryptedData.c_str(), encryptedData.size(), 0);
    break;}
    default:
        cerr << "Invalid choice\n";
        break;
}}


    // Close socket
    close(client_socket);

    return 0;
}


//g++ -std=c++11 -o c  client.cpp -lcryptopp -no-pie

