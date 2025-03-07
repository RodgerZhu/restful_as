#include <stdio.h>
#include <vector>
#include <string>
#include <assert.h>
#include <fstream>

#include <cstring>

#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"

#include <iostream>
#include <stdexcept>
#include <ctime>
#include <openssl/ssl.h>
#include "httplib.h"
#include <nlohmann/json.hpp>

#if SGX_QPL_LOGGING
#include "sgx_default_quote_provider.h"
#ifdef _MSC_VER
typedef quote3_error_t(*sgx_ql_set_logging_callback_t)(sgx_ql_logging_callback_t, sgx_ql_log_level_t);
#endif
#endif

#ifndef _MSC_VER

#define SAMPLE_ISV_ENCLAVE "enclave.signed.so"
#define DEFAULT_QUOTE "../QuoteGenerationSample/quote.dat"

#else

#define SAMPLE_ISV_ENCLAVE "enclave.signed.dll"
#define DEFAULT_QUOTE "..\\..\\..\\QuoteGenerationSample\\x64\\Debug\\quote.dat"
#define QPL_LIB_NAME "dcap_quoteprov.dll"
#define strncpy strncpy_s
#endif
#ifndef SGX_CDECL
#define SGX_CDECL
#endif

using namespace httplib;
using namespace std;

namespace nlohmann {
    template <>
    struct adl_serializer<std::vector<uint8_t>> {
        static void to_json(json& j, const std::vector<uint8_t>& data) {
            j = json::binary(data);
        }
        static void from_json(const json& j, std::vector<uint8_t>& data) {
            data = j.get_binary();
        }
    };
}
using json = nlohmann::json;
#define log(msg, ...)                             \
    do                                            \
    {                                             \
        printf("[APP] " msg "\n", ##__VA_ARGS__); \
        fflush(stdout);                           \
    } while (0)

typedef union _supp_ver_t
{
    uint32_t version;
    struct
    {
        uint16_t major_version;
        uint16_t minor_version;
    };
} supp_ver_t;

vector<uint8_t> readBinaryContent(const string &filePath)
{
    ifstream file(filePath, ios::binary);
    if (!file.is_open())
    {
        log("Error: Unable to open quote file %s", filePath.c_str());
        return {};
    }

    file.seekg(0, ios_base::end);
    streampos fileSize = file.tellg();

    file.seekg(0, ios_base::beg);
    vector<uint8_t> retVal(fileSize);
    file.read(reinterpret_cast<char *>(retVal.data()), fileSize);
    file.close();
    return retVal;
}
#define PATHSIZE 0x418U

/**
 * @param quote - ECDSA quote buffer
 * @param use_qve - Set quote verification mode
 *                   If true, quote verification will be performed by Intel QvE
 *                   If false, quote verification will be performed by untrusted QVL
 */

int ecdsa_quote_verification(vector<uint8_t> quote, bool use_qve)
{
    (void)use_qve;

    int ret = 0;
    time_t current_time = 0;
    quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    

    tee_supp_data_descriptor_t supp_data;

    // You can also set specify a major version in this structure, then we will always return supplemental data of the major version
    // set major verison to 0 means always return latest supplemental data
    memset(&supp_data, 0, sizeof(tee_supp_data_descriptor_t));

    supp_ver_t latest_ver;


    {
        // call DCAP quote verify library to get supplemental latest version and data size
        // version is a combination of major_version and minor version
        // you can set the major version in 'supp_data.major_version' to get old version supplemental data
        // only support major_version 3 right now
        dcap_ret = tee_get_supplemental_data_version_and_size(quote.data(),
                                                              (uint32_t)quote.size(),
                                                              &latest_ver.version,
                                                              &supp_data.data_size);

        if (dcap_ret == SGX_QL_SUCCESS  && supp_data.data_size == sizeof(sgx_ql_qv_supplemental_t))
        {
            log("Info: tee_get_quote_supplemental_data_version_and_size successfully returned.");
            log("Info: latest supplemental data major version: %d, minor version: %d, size: %d", latest_ver.major_version, latest_ver.minor_version, supp_data.data_size);
            supp_data.p_data = (uint8_t *)malloc(supp_data.data_size);
            if (supp_data.p_data != NULL)
            {
                memset(supp_data.p_data, 0, supp_data.data_size);
            }

            // Just print error in sample
            //
            else
            {
                log("Error: Cannot allocate memory for supplemental data.");
                supp_data.data_size = 0;
            }
        }
        else
        {
            if (dcap_ret != SGX_QL_SUCCESS )
                log("Error: tee_get_quote_supplemental_data_size failed: 0x%04x", dcap_ret);

            if (supp_data.data_size != sizeof(sgx_ql_qv_supplemental_t))
                log("Warning: Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.");

            supp_data.data_size = 0;
        }

        // set current time. This is only for sample purposes, in production mode a trusted time should be used.
        //
        current_time = time(NULL);

        // call DCAP quote verify library for quote verification
        // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
        // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
        // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
        dcap_ret = tee_verify_quote(
            quote.data(), (uint32_t)quote.size(),
            NULL,
            current_time,
            &collateral_expiration_status,
            &quote_verification_result,
            NULL,
            &supp_data);
        if (dcap_ret == SGX_QL_SUCCESS )
        {
            log("Info: App: tee_verify_quote successfully returned.");
        }
        else
        {
            log("Error: App: tee_verify_quote failed: 0x%04x", dcap_ret);
            goto cleanup;
        }

        // check verification result
        //
        switch (quote_verification_result)
        {
        case SGX_QL_QV_RESULT_OK:
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            //
            if (collateral_expiration_status == 0)
            {
                log("Info: App: Verification completed successfully.");
                ret = 0;
            }
            else
            {
                log("Warning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
                ret = 1;
            }
            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            log("Warning: App: Verification completed with Non-terminal result: %x", quote_verification_result);
            ret = 1;
            break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            log("Error: App: Verification completed with Terminal result: %x", quote_verification_result);
            ret = -1;
            break;
        }

        // check supplemental data if necessary
        //
        if (dcap_ret == SGX_QL_SUCCESS  && supp_data.p_data != NULL && supp_data.data_size > 0)
        {
            sgx_ql_qv_supplemental_t *p = (sgx_ql_qv_supplemental_t *)supp_data.p_data;

            // you can check supplemental data based on your own attestation/verification policy
            // here we only print supplemental data version for demo usage
            //
            log("Info: Supplemental data Major Version: %d", p->major_version);
            log("Info: Supplemental data Minor Version: %d", p->minor_version);

            // print SA list if exist, SA list is supported from version 3.1
            //
            if (p->version > 3 && strlen(p->sa_list) > 0)
            {
                log("Info: Advisory ID: %s", p->sa_list);
            }
        }
    }

cleanup:
    if (supp_data.p_data != NULL)
    {
        free(supp_data.p_data);
    }


    return ret;
}

void usage()
{
    log("Usage:");
    log("\tPlease specify quote path, e.g. \"./app -quote <path/to/quote>\"");
    log("\t\tDefault quote path is %s when no command line args", DEFAULT_QUOTE);
}


/* Application entry */
void handle_tdx_attestation(const Request& req, Response& res)
{
   // int ret = 0;
    vector<uint8_t> quote;
#if defined(_MSC_VER)
    HINSTANCE qpl_library_handle = NULL;
#endif

    char quote_path[PATHSIZE] = "/root/quote.dat";

    std::cout << "------> handle_tdx_attestation " << std::endl;
    try {
       // auto json_data = json::parse(req.body);
       // TdxQuote quote = json_data.get<TdxQuote>();

       // bool is_valid = validator.validate(quote);
        bool is_valid=1;
        json response = {
            {"attestation_result", is_valid ? "SUCCESS" : "FAILED"},
            {"trust_level", is_valid ? 3 : 0},
            {"timestamp", static_cast<uint32_t>(time(nullptr))}
        };

        std::cout << "------> fill response with attest result  " << std::endl;
        res.set_content(response.dump(), "application/json");

    } catch (const json::exception& e) {
        res.status = 400;
        res.set_content(json{{"error", "JSON_PARSE_ERROR"}, {"message", e.what()}}.dump(), "application/json");
    } catch (const std::exception& e) {
        res.status = 500;
        res.set_content(json{{"error", "TDX_VALIDATION_ERROR"}, {"message", e.what()}}.dump(), "application/json");
    }

    if (*quote_path == '\0')
    {
        strncpy(quote_path, DEFAULT_QUOTE, PATHSIZE - 1);
    }

    // read quote from file
    //
    quote = readBinaryContent(quote_path);
    if (quote.empty())
    {
        std::cout << "------> No Quote Data Received!  " << std::endl;
       // usage();
       // return -1;
    }


    log("Info: ECDSA quote path: %s", quote_path);

    // Trusted quote verification, ignore error checking

    // Unrusted quote verification, ignore error checking
    log("Untrusted quote verification:");
    if (ecdsa_quote_verification(quote, false) != 0)
    {
        std::cout << "------> Untrusted Quote verification fail " << std::endl;
    }

    //return ret;
}

int SGX_CDECL main()
{
    httplib::Server svr;
    //SSLServer svr;
    svr.Post("/tdx_attest", handle_tdx_attestation);
    svr.set_read_timeout(10);
    svr.set_write_timeout(10);

    std::cout << "Starting TDX Attestation Service on port 8443..." << std::endl;
    svr.listen("localhost", 8443);
}
