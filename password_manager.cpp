#include <iostream>
#include <iomanip>
#include <string>
#include <limits>
#include <memory>
#include <fstream>
#include <vector>
#include <algorithm>

// Struct representing a credential
struct Credential
{
    std::string username;
    std::string password;

    Credential(const std::string &u, const std::string &p)
        : username(u), password(p) {}
};

// Class representing a Password Manager
class PasswordManager
{
private:
    std::string masterPassword;
    std::string secretKey;
    std::vector<std::shared_ptr<Credential>> credentials;

    // Basic XOR encryption function
    std::string encrypt(const std::string &input) const
    {
        std::string result = input;

        for (size_t i = 0; i < input.length(); ++i)
            result[i] = input[i] ^ secretKey[i % secretKey.length()];

        return result;
    }

    // Basic XOR decryption function
    std::string decrypt(const std::string &input) const
    {
        return encrypt(input);
    }

    // Validate the format of a username
    bool isValidUsername(const std::string &username) const
    {
        return !username.empty() && std::all_of(username.begin(), username.end(), ::isalnum);
    }

    // Validate the format of a password
    bool isValidPassword(const std::string &password) const
    {
        return password.length() >= 8;
    }

public:
    static bool isSecurePassword(const std::string &password)
    {
        // Validate if the password meets security criteria
        const size_t minLength = 8;
        bool hasUppercase = false;
        bool hasLowercase = false;
        bool hasDigit = false;
        bool hasSpecialChar = false;

        for (char ch : password)
        {
            if (std::isupper(ch))
                hasUppercase = true;
            else if (std::islower(ch))
                hasLowercase = true;
            else if (std::isdigit(ch))
                hasDigit = true;
            else if (std::ispunct(ch))
                hasSpecialChar = true;
        }

        return password.length() >= minLength &&
               hasUppercase &&
               hasLowercase &&
               hasDigit &&
               hasSpecialChar;
    }

    // Function to set a master password
    void setMasterPassword(const std::string &password)
    {
        masterPassword = password;
        std::cout << "Master password set successfully." << std::endl;
    }

    // Function to set a secret key for encryption and decryption
    void setSecretKey(const std::string &key)
    {
        secretKey = key;
    }

    // Function to authenticate the user
    bool authenticateUser(const std::string &enteredPassword) const
    {
        return enteredPassword == masterPassword;
    }

    // Function to add a new credential with input validation
    void addCredential(const std::string &username)
    {
        if (!isValidUsername(username))
        {
            std::cerr << "Invalid username format. It should contain only alphanumeric characters." << std::endl;
            return;
        }

        // Generate a random password
        std::string password = generateRandomPassword(12); // Using password of length 12

        // Check if the username already exists
        auto it = std::find_if(credentials.begin(), credentials.end(),
                               [&](const std::shared_ptr<Credential> &cred)
                               { return cred->username == username; });

        if (it != credentials.end())
        {
            // Username already exists, update the password
            (*it)->password = password;

            std::cout << "Password updated for username: " << username << std::endl;
            std::cout << "New Password: " << password << std::endl;
        }
        else
        {
            // Username doesn't exist, add a new credential
            auto newCredential = std::make_shared<Credential>(username, password);
            credentials.push_back(newCredential);

            std::cout << "Credential added for username: " << username << std::endl;
            std::cout << "Generated Password: " << password << std::endl;
        }
    }

    // Load credentials form file
    void loadCredential(const std::string &username, const std::string &password)
    {
        // Check if the username already exists
        auto it = std::find_if(credentials.begin(), credentials.end(),
                               [&](const std::shared_ptr<Credential> &cred)
                               { return cred->username == username; });

        if (it != credentials.end())
        {
            // Username already exists, update the password
            (*it)->password = password;
        }
        else
        {
            // Username doesn't exist, add credential
            auto newCredential = std::make_shared<Credential>(username, password);
            credentials.push_back(newCredential);
        }
    }

    // Function to retrieve a password for a given username
    void retrieveCredential(const std::string &username) const
    {
        auto it = std::find_if(credentials.begin(), credentials.end(),
                               [&](const std::shared_ptr<Credential> &cred)
                               { return cred->username == username; });

        if (it != credentials.end())
        {
            std::cout << "Retrieved Password for username " << username << ": " << (*it)->password << std::endl;
        }
        else
        {
            std::cout << "Password not found for the given username." << std::endl;
        }
    }

    // Function to delete all credentials for a given username
    void deleteCredentials(const std::string &username)
    {
        credentials.erase(std::remove_if(credentials.begin(), credentials.end(),
                                         [&](const std::shared_ptr<Credential> &cred)
                                         { return cred->username == username; }),
                          credentials.end());
        std::cout << "Credentials deleted for username: " << username << std::endl;
    }

    // Function to generate a secure random password
    std::string generateRandomPassword(int minLength = 8)
    {
        const std::string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const std::string lower = "abcdefghijklmnopqrstuvwxyz";
        const std::string digits = "0123456789";
        const std::string specials = "!@#$%^&*()-=_+";

        srand(static_cast<unsigned int>(time(0)));

        // Making sure that at least one character from all group included in password
        std::string password;
        password.push_back(upper[rand() % upper.length()]);
        password.push_back(lower[rand() % lower.length()]);
        password.push_back(digits[rand() % digits.length()]);
        password.push_back(specials[rand() % specials.length()]);

        const std::string allChars = upper + lower + digits + specials;

        for (int i = password.length(); i < minLength; ++i)
            password.push_back(allChars[rand() % allChars.length()]);

        std::random_shuffle(password.begin(), password.end());

        return password;
    }

    // Function to save credentials to a file
    void saveToFile(const std::string &filename) const
    {
        std::ofstream outFile(filename, std::ios::binary);
        if (outFile.is_open())
        {
            for (const auto &cred : credentials)
            {
                outFile << cred->username << '\t' << encrypt(cred->password) << '\n';
            }
            outFile.close();
        }
        else
        {
            std::cerr << "Unable to open file for writing." << std::endl;
        }
    }

    // Function to load credentials from a file
    void loadFromFile(const std::string &filename)
    {
        std::ifstream inFile(filename, std::ios::binary);
        if (inFile.is_open())
        {
            std::string line;
            // Read and parse each line from the file
            while (std::getline(inFile, line))
            {
                std::istringstream iss(line);
                std::string username, encryptedPassword;

                // Extract username and password from the line
                if (iss >> username >> encryptedPassword)
                {
                    std::string decryptedPassword = decrypt(encryptedPassword);
                    loadCredential(username, decryptedPassword);
                    std::cout << "Retrieved Password for username " << username << ": " << decryptedPassword << std::endl;
                }
                else
                {
                    std::cerr << "Error parsing line: " << line << std::endl;
                }
            }

            // Close the file
            inFile.close();
        }
        else
        {
            std::cerr << "Unable to open file for reading." << std::endl;
        }
    }
};

// Main function demonstrating the Password Manager interface
int main()
{
    PasswordManager passwordManager;

    // Set secret key for encryption and decryption
    passwordManager.setSecretKey("mySecretKey");

    // Set secure master password
    std::string masterPassword;
    bool isSecure = false;
    do
    {
        std::cout << "Set your master password: ";
        std::getline(std::cin, masterPassword);

        isSecure = PasswordManager::isSecurePassword(masterPassword);

        if (!isSecure)
        {
            std::cout << "Please enter atleast one uppercase, lowercase, digits, and special characters.\n";
        }
    } while (!isSecure);

    passwordManager.setMasterPassword(masterPassword);

    // Authenticate the user
    std::string enteredPassword;
    std::cout << "Enter your master password: ";
    std::getline(std::cin, enteredPassword);

    if (passwordManager.authenticateUser(enteredPassword))
    {
        std::cout << "Authentication successful!" << std::endl;

        int choice;
        do
        {
            // Display menu
            std::cout << "\n=== Password Manager Menu ===" << std::endl;
            std::cout << "1. Add Credentials" << std::endl;
            std::cout << "2. Get Credentials" << std::endl;
            std::cout << "3. Delete Credentials" << std::endl;
            std::cout << "4. Save to File" << std::endl;
            std::cout << "5. Load from File" << std::endl;
            std::cout << "6. Exit" << std::endl;

            // Get user choice
            std::cout << "Enter your choice: ";
            while (!(std::cin >> choice) || choice < 1 || choice > 6)
            {
                std::cout << "Invalid choice. Please enter a number between 1 and 6." << std::endl;

                // Clear input buffer
                std::cin.clear();
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            }

            // Clear input buffer
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            // Perform actions based on user choice
            switch (choice)
            {
            case 1:
            {
                std::string username;
                std::cout << "Enter username: ";
                std::getline(std::cin, username);
                passwordManager.addCredential(username);
                break;
            }
            case 2:
            {
                std::string username;
                std::cout << "Enter username: ";
                std::getline(std::cin, username);
                passwordManager.retrieveCredential(username);
                break;
            }
            case 3:
            {
                std::string username;
                std::cout << "Enter username: ";
                std::getline(std::cin, username);
                passwordManager.deleteCredentials(username);
                break;
            }
            case 4:
            {
                std::string filename;
                std::cout << "Enter filename to save: ";
                std::getline(std::cin, filename);
                passwordManager.saveToFile(filename);
                break;
            }
            case 5:
            {
                std::string filename;
                std::cout << "Enter filename to load: ";
                std::getline(std::cin, filename);

                std::ifstream file(filename);
                if (file.is_open())
                {
                    passwordManager.loadFromFile(filename);
                    file.close();
                }
                else
                {
                    std::cerr << "Error: Unable to open the file '" << filename << "' for reading." << std::endl;
                }
                break;
            }

            case 6:
                std::cout << "Exiting Password Manager. Goodbye!" << std::endl;
                break;
            default:
                std::cout << "Invalid choice. Please enter a number between 1 and 6." << std::endl;
            }

        } while (choice != 6);
    }
    else
    {
        std::cout << "Authentication failed. Exiting..." << std::endl;
        return 1; // Exit with an error code
    }

    return 0;
}
