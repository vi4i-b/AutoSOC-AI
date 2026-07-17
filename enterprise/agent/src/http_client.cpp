#include "http_client.hpp"

#include <curl/curl.h>

namespace autosoc {

static size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

HttpResponse ServerFailover::do_post(const std::string& base, const std::string& path,
                                     const std::string& json_body) {
    HttpResponse r;
    r.server = base;
    CURL* curl = curl_easy_init();
    if (!curl) {
        r.error = "curl init failed";
        return r;
    }
    std::string url = base + path;
    std::string response;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(json_body.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, cfg_.http_timeout_ms);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 4000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);  // thread-safe timeouts

    CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK) {
        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        r.status = status;
        r.body = response;
        r.ok = status > 0 && status < 400;
        if (!r.ok) r.error = "HTTP " + std::to_string(status);
    } else {
        r.error = curl_easy_strerror(rc);
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return r;
}

void ServerFailover::advance() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!cfg_.servers.empty()) active_ = (active_ + 1) % cfg_.servers.size();
}

HttpResponse ServerFailover::post_json(const std::string& path, const std::string& json_body) {
    if (cfg_.servers.empty()) {
        HttpResponse r;
        r.error = "no servers configured";
        return r;
    }
    // Try every server once, starting from the active one.
    for (size_t attempt = 0; attempt < cfg_.servers.size(); ++attempt) {
        std::string base;
        {
            std::lock_guard<std::mutex> lock(mu_);
            base = cfg_.servers[active_];
        }
        HttpResponse r = do_post(base, path, json_body);
        // A transport error (not an HTTP error) triggers failover to a backup.
        if (r.status != 0 || r.ok) return r;
        advance();
    }
    HttpResponse r;
    r.error = "all servers unreachable";
    return r;
}

}  // namespace autosoc
