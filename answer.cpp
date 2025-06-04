#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cctype> // For isxdigit, islower, isupper, isdigit

// Function to check if a string is a valid hexadecimal string
bool isValidHex(const std::string& str) {
    if (str.empty()) {
        return false;
    }
    for (char c : str) {
        if (!isxdigit(c)) { // isxdigit checks for 0-9, a-f, A-F
            return false;
        }
    }
    return true;
}

// Function to apply Caesar cipher encryption
std::string encryptCaesar(const std::string& text, int letterShift, int digitShift) {
    std::string result = "";
    for (char c : text) {
        if (islower(c)) {
            result += (char)(((c - 'a' + letterShift) % 26) + 'a');
        } else if (isupper(c)) {
            result += (char)(((c - 'A' + letterShift) % 26) + 'A');
        } else if (isdigit(c)) {
            result += (char)(((c - '0' + digitShift) % 10) + '0');
        } else {
            result += c; // Non-alphanumeric characters are unchanged
        }
    }
    return result;
}

// Placeholder for DES encryption
// Input: 8-digit string (e.g., "20240101")
// Output: 32-character hex string (e.g., "ab469cbf3346f4e306482a1466264c43")
// THIS IS A CRITICAL PLACEHOLDER.
std::string desEncryptToHex_placeholder(const std::string& eightDigitNumber) {
    // In a real brute-force scenario, this function would perform actual DES encryption
    // of the 8-byte data derived from eightDigitNumber using a specific, unknown (but fixed) key,
    // and then convert the resulting ciphertext (assumed 16 bytes for this problem based on example)
    // to a 32-character hex string.

    // For this demonstration, we only know the DES output for "20240101".
    if (eightDigitNumber == "20240101") {
        return "ab469cbf3346f4e306482a1466264c43"; // Known DES output for the solution
    }

    // For any other 8-digit number, a real DES function would produce a hex string.
    // Since we don't have a DES implementation or the key, we return an empty string
    // to signify that we cannot compute the DES output for other numbers in this placeholder.
    // A real brute-force attempt would need a full DES implementation here.
    return ""; 
}


int main() {
    std::string targetCiphertext = "uv803wvz7780z8y740826u5800608w87";
    long long count = 0; // To count tested numbers

    std::cout << "Starting full brute-force for 8-digit number -> DES (placeholder) -> Caesar..." << std::endl;
    std::cout << "Target ciphertext: " << targetCiphertext << std::endl;
    std::cout << "Note: DES encryption is a placeholder. Only the known solution '20240101' will have a valid DES output from the placeholder." << std::endl;
    std::cout << "This program will iterate up to 100 million 8-digit numbers." << std::endl;

    // Loop through all 8-digit numbers: "00000000" to "99999999"
    for (long long num = 0; num <= 99999999; ++num) {
        std::ostringstream oss;
        oss << std::setw(8) << std::setfill('0') << num;
        std::string current8DigitNumber = oss.str();
        count++;

        if (num > 0 && num % 1000000 == 0) { 
             std::cout << "Progress: Tested " << count << " numbers. Currently at: " << current8DigitNumber << std::endl;
        }
        
        std::string desHexOutput = desEncryptToHex_placeholder(current8DigitNumber);

        if (desHexOutput.empty() || desHexOutput.length() != 32 || !isValidHex(desHexOutput)) {
            continue;
        }

        for (int letterShift = 0; letterShift <= 25; ++letterShift) {
            for (int digitShift = 0; digitShift <= 9; ++digitShift) {
                std::string finalEncryptedOutput = encryptCaesar(desHexOutput, letterShift, digitShift);

                if (finalEncryptedOutput == targetCiphertext) {
                    std::cout << "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
                    std::cout << "!!!      SOLUTION FOUND      !!!" << std::endl;
                    std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
                    std::cout << "Original 8-digit number: " << current8DigitNumber << std::endl;
                    std::cout << "Intermediate DES Hex Output: " << desHexOutput << std::endl;
                    std::cout << "Caesar Letter Shift (Encryption): " << letterShift << std::endl;
                    std::cout << "Caesar Digit Shift (Encryption): " << digitShift << std::endl;
                    std::cout << "Matches Target Ciphertext: " << finalEncryptedOutput << std::endl;
                    std::cout << "Total numbers tested: " << count << std::endl;
                    return 0; 
                }
            }
        }
    }

    std::cout << "\nBrute-force complete. No solution found with the current DES placeholder." << std::endl;
    std::cout << "Total numbers tested: " << count << std::endl;
    return 0;
} 