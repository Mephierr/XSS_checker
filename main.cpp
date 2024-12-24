#include <iostream>
#include <string>
#include <curl/curl.h>

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

bool checkXSS(const std::string& url) {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    // Инициализация libcurl
    curl = curl_easy_init();
    if(curl) {
        // Формируем URL с потенциальным XSS
        std::string testUrl = url + "?input=<script>alert('XSS')</script>";

        // Устанавливаем URL
        curl_easy_setopt(curl, CURLOPT_URL, testUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");

        // Выполняем запрос
        res = curl_easy_perform(curl);

        // Проверяем на ошибки
        if(res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            curl_easy_cleanup(curl);
            return false;
        }

        // Освобождаем ресурсы
        curl_easy_cleanup(curl);

        // Проверяем ответ на наличие скрипта
        if (readBuffer.find("<script>") != std::string::npos) {
            std::cout << "Уязвимость к XSS найдена!" << std::endl;
            return true;
        } else {
            std::cout << "XSS уязвимость не найдена." << std::endl;
            return false;
        }
    }
    return false;
}

int main() {
    std::string url;
    std::cout << "Введите URL для проверки: ";
    std::cin >> url;

    checkXSS(url);

    return 0;
}
