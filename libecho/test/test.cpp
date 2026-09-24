#include <iostream>
#include <cassert>
#include <cstring>
#include <string>
#include "../libecho/libecho.h"
#include <google/protobuf/descriptor.h>
#include <google/protobuf/dynamic_message.h>
#include <google/protobuf/compiler/importer.h>

void test_port()
{
    int port = get_port();
    std::cout << "[TEST] Port is: " << port << std::endl;
    assert(port == 12345);
    std::cout << "[PASS] test_port" << std::endl;
}

void test_get_msg_name()
{
    const char *name1 = get_msg_name(1001);
    std::cout << "[TEST] Msg 1001 name: " << name1 << std::endl;
    assert(std::string(name1) == "testpkg.LoginRequest");

    const char *name2 = get_msg_name(1002);
    std::cout << "[TEST] Msg 1002 name: " << name2 << std::endl;
    assert(std::string(name2) == "testpkg.LoginResponse");

    const char *unknown = get_msg_name(9999);
    assert(std::string(unknown) == "unknown");
    std::cout << "[PASS] test_get_msg_name" << std::endl;
}

void test_show_msg()
{
    // Build a protobuf dynamic message to serialize
    google::protobuf::compiler::DiskSourceTree sourceTree;
    sourceTree.MapPath("", "./");
    google::protobuf::compiler::Importer importer(&sourceTree, nullptr);
    const google::protobuf::FileDescriptor *fd = importer.Import("test.proto");
    assert(fd != nullptr);

    const google::protobuf::Descriptor *desc = fd->FindMessageTypeByName("LoginRequest");
    assert(desc != nullptr);

    google::protobuf::DynamicMessageFactory factory;
    const google::protobuf::Message *prototype = factory.GetPrototype(desc);
    assert(prototype != nullptr);

    std::unique_ptr<google::protobuf::Message> msg(prototype->New());
    const google::protobuf::Reflection *ref = msg->GetReflection();

    const google::protobuf::FieldDescriptor *fd_user = desc->FindFieldByName("username");
    const google::protobuf::FieldDescriptor *fd_pass = desc->FindFieldByName("password");
    const google::protobuf::FieldDescriptor *fd_ver = desc->FindFieldByName("client_version");

    ref->SetString(msg.get(), fd_user, "alice");
    ref->SetString(msg.get(), fd_pass, "secret123");
    ref->SetInt32(msg.get(), fd_ver, 42);

    std::string serialized;
    bool ok = msg->SerializeToString(&serialized);
    assert(ok);

    const char *decoded = show_msg(1001, serialized.data(), static_cast<int>(serialized.size()));
    std::cout << "[TEST] Decoded output:\n" << decoded << std::endl;

    assert(std::string(decoded).find("alice") != std::string::npos);
    assert(std::string(decoded).find("secret123") != std::string::npos);
    assert(std::string(decoded).find("42") != std::string::npos);
    std::cout << "[PASS] test_show_msg" << std::endl;

    // Test unknown ID
    const char *err1 = show_msg(9999, serialized.data(), static_cast<int>(serialized.size()));
    assert(std::string(err1) == "(unknown message id)");

    // Test malformed payload
    const char corrupted[] = "\xFF\xFF\xFF\xFF";
    const char *err2 = show_msg(1001, corrupted, sizeof(corrupted));
    assert(std::string(err2).find("ParseFromArray failed") != std::string::npos);

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
