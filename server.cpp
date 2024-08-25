#include <iostream>
#include <fstream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <unordered_map>
#include <signal.h>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <crypto++/sha.h>
#include <crypto++/hex.h>
#include <crypto++/filters.h>
#include <crypto++/files.h>
#include <crypto++/cryptlib.h>
#include <crypto++/osrng.h>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/types.h>

using namespace std;
namespace fs = std::filesystem;
using namespace CryptoPP;

unordered_map<string, string> fileData;

int client_socket;
int server_socket;

void closeSockets(int signo) {
    cout << "Closing sockets..." << endl;
    close(client_socket);
    close(server_socket);
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

// Structure to hold user data
struct UserData {
    string username;
    string salt;
    string hashedPassword;
};

// Function to generate a random salt
string GenerateSalt() {
    AutoSeededRandomPool prng;
    CryptoPP::byte salt[16];
    prng.GenerateBlock(salt, sizeof(salt));

    string encodedSalt;
    StringSource(salt, sizeof(salt), true, new HexEncoder(new StringSink(encodedSalt)));

    return encodedSalt;
}

// Function to hash a password with a given salt
string HashPassword(const string& password, const string& salt) {
    string hashed;
    SHA512 hash;
    StringSource(password + salt, true,
        new HashFilter(hash, new HexEncoder(new StringSink(hashed))));

    return hashed;
}

// Function to store user data in a file
void StoreUserData(const UserData& userData) {
    ofstream file("users.txt", ios::app);
    if (file.is_open()) {
        file << userData.username << " " << userData.salt << " " << userData.hashedPassword << endl;
        file.close();
    } else {
        cerr << "Error opening file for writing" << endl;
    }
}

// Function to read user data from file
vector<UserData> ReadUserData() {
    vector<UserData> userDataList;
    ifstream file("users.txt");
    if (file.is_open()) {
        string line;
        while (getline(file, line)) {
            stringstream ss(line);
            UserData userData;
            ss >> userData.username >> userData.salt >> userData.hashedPassword;
            userDataList.push_back(userData);
        }
        file.close();
    } else {
        cerr << "Error opening file for reading" << endl;
    }
    return userDataList;
}

// Function to verify login credentials
bool VerifyLogin(const string& username, const string& password, const vector<UserData>& userDataList) {
    for (const auto& userData : userDataList) {
        if (userData.username == username) {
            string hashedPassword = HashPassword(password, userData.salt);
            if (hashedPassword == userData.hashedPassword) {
                return true; // Login successful
            }
        }
    }
    return false; // Login failed
}



void createFile(const string str,const string username, const string& data) {
string str2=username+"/";
str2+=str;
    ofstream file(str2);
   if (file.is_open()) {
        file << data;
        file.close();}
    
    else {
       cerr << "Error creating file: " << str2<< endl;
    }
}

string readFile(const string str,const string username) {
string str2=username+"/";
str2+=str;
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

void modifyFile(const string str,const string username, const string newData) {
string str2=username+"/";
str2+=str;
    remove(str2.c_str());  // Delete old file
    cout<<"writing into file data : "<<newData<<endl;
    
    createFile(str, username,newData);  // Create new file with modified data
}

void deleteFile(const string& str,const string username) {
string str2=username+"/";
str2+=str;
    remove(str2.c_str());  // Delete file
}

int handleClientRequest(const string username) {
    // Receive choice from client
    char choice;
    int bytes_received = recv(client_socket, &choice, sizeof(choice), 0);
    if (bytes_received <= 0) {
        cerr << "Error receiving choice from client\n";
        close(client_socket);
        return -1;
    }

    // Handle client choice
   char fileName[1024],data[1024];
    switch (choice) {
         case '1':  // Creation
    {
         
        bytes_received = recv(client_socket, fileName, sizeof(fileName) - 1, 0);
        if (bytes_received <= 0) {
            cerr << "Error receiving file name from client\n";
            close(client_socket);
            return -1;
        }
        fileName[bytes_received] = '\0'; 
        cout << "Received file name: " << fileName << endl;

        createFile(fileName,username, "");
        cout << "Created file: " << fileName << endl;
        break;
    }
        case '2':  // Reading
             {
        bytes_received = recv(client_socket, fileName, sizeof(fileName) - 1, 0);
        if (bytes_received <= 0) {
            cerr << "Error receiving file name from client\n";
            close(client_socket);
            return -1;
        }
        fileName[bytes_received] = '\0';
        cout << "Received file name: " << fileName << endl;
        string data2;
            data2 = readFile(fileName,username);
            
            cout<<"data sending to client : "<<data2<<endl;
            cout<<"length : "<<data2.size()<<endl;
            send(client_socket, data2.c_str(), data2.size(), 0);
            break;}
            
            
        case '3': { // Deletion
             
        bytes_received = recv(client_socket, fileName, sizeof(fileName) - 1, 0);
        if (bytes_received <= 0) {
            cerr << "Error receiving file name from client\n";
            close(client_socket);
            return -1;
        }
        fileName[bytes_received] = '\0'; // Null-terminate the received string
        cout << "Received file name: " << fileName << endl;
        
            deleteFile(fileName,username);
            cout << "Deleted file: " << fileName << endl;
            break;}
            
            
        case '4': { // Modification
             
        bytes_received = recv(client_socket, fileName, sizeof(fileName) - 1, 0);
        if (bytes_received <= 0) {
            cerr << "Error receiving file name from client\n";
            close(client_socket);
            return -1;
        }
        fileName[bytes_received] = '\0'; // Null-terminate the received string
        cout << "Received file name: " << fileName << endl;
        
            bytes_received = recv(client_socket, data, sizeof(data)-1, 0);
            if (bytes_received <= 0) {
                cerr << "Error receiving modified data from client\n";
                close(client_socket);
                return -1;
            }
             data[bytes_received] = '\0'; // Null-terminate the received string
             cout<<"encrypted ffrom client : "<<data<<endl;
             cout<<"length is "<<bytes_received<<endl;
             
            modifyFile(fileName,username, data);
            cout << "Modified file: " << fileName << endl;
            break;}
            
        default:
            cerr << "Invalid choice from client\n";
            break;
    }
    return 1;
}
string func(string username){
 fs::path folderPath = username;
string temp="";
for (const auto& entry : fs::directory_iterator(folderPath)) {
            temp+=entry.path().filename() ;
            temp+="\n";
        }
  return temp;}


int main() {
    signal(SIGINT, closeSockets);

   
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        cerr << "Error creating server socket\n";
        return 1;
    }

    
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(8085);

    if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) {
        cerr << "Error binding server socket\n";
        return 2;
    }

   
    if (listen(server_socket, SOMAXCONN) == -1) {
        cerr << "Error listening for connections\n";
        return 3;
    }

    cout << "Server started. Waiting for connections...\n";

    while (true) {
       
        client_socket = accept(server_socket, nullptr, nullptr);
        if (client_socket == -1) {
            cerr << "Error accepting connection\n";
            continue;
        }

        cout << "Client connected\n";
         vector<UserData> userDataList = ReadUserData();
         string username;
         
         // Receive choice from client (signup or login)
    char choiceBuffer[1024];
    int choiceBytesReceived = recv(client_socket, choiceBuffer, sizeof(choiceBuffer), 0);
    if (choiceBytesReceived == -1) {
        cerr << "Error receiving choice" << endl;
        close(client_socket);
        close(server_socket);
        return 1;
    }

    // Process client's choice
    string choice(choiceBuffer, choiceBytesReceived);
    if (choice == "signup") {
        // Receive signup data (username and password)
        char signupBuffer[1024];
        int signupBytesReceived = recv(client_socket, signupBuffer, sizeof(signupBuffer), 0);
        if (signupBytesReceived == -1) {
            cerr << "Error receiving signup data" << endl;
            close(client_socket);
            close(server_socket);
            return 1;
        }

        // Parse signup data
        string signupData(signupBuffer, signupBytesReceived);
        size_t pos = signupData.find(' ');
        if (pos != string::npos) {
            UserData userData;
            userData.username = signupData.substr(0, pos);
            string password = signupData.substr(pos + 1);
            username=userData.username;

            // Generate salt and hash password
            userData.salt = GenerateSalt();
            userData.hashedPassword = HashPassword(password, userData.salt);

            // Store user data
            StoreUserData(userData);

            cout << "User signed up: " << userData.username << endl;
               
    if (createDirectory(userData.username)) {
        cout << "Directory '" << userData.username<< "' created successfully." << endl;
    }
        } else {
            cerr << "Invalid signup data format" << endl;
        }
    } 
    else if (choice == "login") {
        // Receive login data (username and password) from client
        char loginBuffer[1024];
        int loginBytesReceived = recv(client_socket, loginBuffer, sizeof(loginBuffer), 0);
        if (loginBytesReceived == -1) {
            cerr << "Error receiving login data" << endl;
            close(client_socket);
            close(server_socket);
            return 1;
        }

        // Parse login data
        string loginData(loginBuffer, loginBytesReceived);
        size_t pos = loginData.find(' ');
        if (pos != string::npos) {
            username = loginData.substr(0, pos);
            string password = loginData.substr(pos + 1);

            // Verify login credentials
            bool loginResult = VerifyLogin(username, password, userDataList);

            // Send login result to client
            string response = loginResult ? "Login successful" : "Login failed";
            if (send(client_socket, response.c_str(), response.size(), 0) == -1) {
                cerr << "Error sending login result" << endl;
                close(client_socket);
                close(server_socket);
                return 1;
            }
            if(response=="Login failed"){close(client_socket);continue;}
    } 
    }else {
        cerr << "Invalid choice from client" << endl;
        close(client_socket);
        continue;
    }



       string contents=func(username);
        //cout<<contents<<endl;
        string menu = "Options:\n1. Create file\n2. Read file\n3. Delete file\n4. Modify file\n  your files .\n";
        menu+=contents;
        send(client_socket, menu.c_str(), menu.size(), 0);
        while(1){
        
        int k=handleClientRequest(username);
        if(k<0)break;

        
       
    }}

     close(client_socket);
    close(server_socket);

    return 0;
}


//g++ -std=c++17 -o s  server.cpp -lcryptopp -no-pie

