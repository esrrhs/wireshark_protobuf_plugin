#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <memory>
#include "../libecho/libecho.h"
#include <google/protobuf/descriptor.h>
#include <google/protobuf/dynamic_message.h>
#include <google/protobuf/compiler/importer.h>

#define TEST_CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[FAIL] (" << __FILE__ << ":" << __LINE__ << "): " << (msg) << std::endl; \
            std::exit(1); \
        } \
    } while (0)

void test_port()
{
    int port = get_port();
    std::cout << "[TEST] Port is: " << port << std::endl;
    TEST_CHECK(port == 12345, "Port must be 12345 (check if config.xml was loaded)");
    std::cout << "[PASS] test_port" << std::endl;
}

void test_get_msg_name()
{
    const char *name1 = get_msg_name(1001);
    std::cout << "[TEST] Msg 1001 name: " << name1 << std::endl;
    TEST_CHECK(std::string(name1) == "testpkg.LoginRequest", "Msg 1001 must be testpkg.LoginRequest");

    const char *name2 = get_msg_name(1002);
    std::cout << "[TEST] Msg 1002 name: " << name2 << std::endl;
    TEST_CHECK(std::string(name2) == "testpkg.LoginResponse", "Msg 1002 must be testpkg.LoginResponse");

    const char *unknown = get_msg_name(9999);
    TEST_CHECK(std::string(unknown) == "unknown", "Unknown message must return 'unknown'");
    std::cout << "[PASS] test_get_msg_name" << std::endl;
}

void test_show_msg()
{
    // Build a protobuf dynamic message to serialize
    google::protobuf::compiler::DiskSourceTree sourceTree;
    sourceTree.MapPath("", "./");
    sourceTree.MapPath("", "Release/");
    sourceTree.MapPath("", "Debug/");
    sourceTree.MapPath("", "../");

    google::protobuf::compiler::Importer importer(&sourceTree, nullptr);
    const google::protobuf::FileDescriptor *fd = importer.Import("test.proto");
    TEST_CHECK(fd != nullptr, "Failed to import test.proto (check file paths)");

    const google::protobuf::Descriptor *desc = fd->FindMessageTypeByName("LoginRequest");
    TEST_CHECK(desc != nullptr, "FindMessageTypeByName('LoginRequest') failed");

    google::protobuf::DynamicMessageFactory factory;
    const google::protobuf::Message *prototype = factory.GetPrototype(desc);
    TEST_CHECK(prototype != nullptr, "GetPrototype failed");

    std::unique_ptr<google::protobuf::Message> msg(prototype->New());
    const google::protobuf::Reflection *ref = msg->GetReflection();

    const google::protobuf::FieldDescriptor *fd_user = desc->FindFieldByName("username");
    const google::protobuf::FieldDescriptor *fd_pass = desc->FindFieldByName("password");
    const google::protobuf::FieldDescriptor *fd_ver = desc->FindFieldByName("client_version");
    TEST_CHECK(fd_user && fd_pass && fd_ver, "FindFieldByName for fields failed");

    ref->SetString(msg.get(), fd_user, "alice");
    ref->SetString(msg.get(), fd_pass, "secret123");
    ref->SetInt32(msg.get(), fd_ver, 42);

    std::string serialized;
    bool ok = msg->SerializeToString(&serialized);
    TEST_CHECK(ok, "SerializeToString failed");

    const char *decoded = show_msg(1001, serialized.data(), static_cast<int>(serialized.size()));
    std::cout << "[TEST] Decoded output:\n" << (decoded ? decoded : "(null)") << std::endl;
    TEST_CHECK(decoded != nullptr, "show_msg returned null pointer");

    std::string decoded_str(decoded);
    TEST_CHECK(decoded_str.find("alice") != std::string::npos, "Decoded output must contain 'alice'");
    TEST_CHECK(decoded_str.find("secret123") != std::string::npos, "Decoded output must contain 'secret123'");
    TEST_CHECK(decoded_str.find("42") != std::string::npos, "Decoded output must contain '42'");
    std::cout << "[PASS] test_show_msg" << std::endl;

    // Test unknown ID
    const char *err1 = show_msg(9999, serialized.data(), static_cast<int>(serialized.size()));
    TEST_CHECK(err1 && std::string(err1) == "(unknown message id)", "Unknown message id check failed");

    // Test malformed payload
    const char corrupted[] = "\xFF\xFF\xFF\xFF";
    const char *err2 = show_msg(1001, corrupted, sizeof(corrupted));
    TEST_CHECK(err2 && std::string(err2).find("ParseFromArray failed") != std::string::npos, "Malformed payload check failed");

    std::cout << "[PASS] test_show_msg_error_handling" << std::endl;
}

int main()
{
    std::cout << "=== Running libecho Unit Tests ===" << std::endl;
    ini_msg();

    test_port();
    test_get_msg_name();
    test_show_msg();

    std::cout << "=== All Unit Tests Passed! ===" << std::endl;
    return 0;
}

