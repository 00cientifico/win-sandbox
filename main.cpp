#include <windows.h>
#include <Sddl.h>
#include <Userenv.h>
#include <AccCtrl.h>
#include <Aclapi.h>
#include <string>
#include <iostream>
#include <format>
#include <functional>
#include <optional>

#pragma comment(lib, "Userenv.lib")

const LPCWSTR CONTAINER_NAME = L"MinecraftSandbox";
const LPCWSTR CONTAINER_DESC = L"Minecraft Sandbox";

void GrantAccess(PSID sid, std::string objectName,
    SE_OBJECT_TYPE objectType, DWORD accessPermissions);
std::string SidToString(PSID sid);
std::optional<std::string> EnvVar(const std::string& key);
std::string GetProcessArgs(const std::vector<std::string>& vec);

// Taken from: https://stackoverflow.com/a/28413370
class scope_guard {
public:
    template<class Callable>
    scope_guard(Callable&& undo_func) try : f(std::forward<Callable>(undo_func)) {
    }
    catch (...) {
        undo_func();
        throw;
    }

    scope_guard(scope_guard&& other) : f(std::move(other.f)) {
        other.f = nullptr;
    }

    ~scope_guard() {
        if (f) f(); // must not throw
    }

    void dismiss() noexcept {
        f = nullptr;
    }

    scope_guard(const scope_guard&) = delete;
    void operator = (const scope_guard&) = delete;

private:
    std::function<void()> f;
};

// Very much a proof of concept, do not trust this or use in production!
int run(int argc, char* argv[]) {
    std::vector<std::string> arguments(argv + 1, argv + argc);

    if (arguments.size() < 2) {
        std::cout << "Expected: <working_dir> ...args" << std::endl;
        return 1;
    }

    PSID sid = nullptr;
    HRESULT result = ::CreateAppContainerProfile(
        CONTAINER_NAME,
        CONTAINER_NAME,
        CONTAINER_DESC,
        NULL,
        0,
        &sid);
    if (HRESULT_CODE(result) == ERROR_ALREADY_EXISTS) {
        result = ::DeriveAppContainerSidFromAppContainerName(CONTAINER_NAME, &sid);

        if (!SUCCEEDED(result)) {
            throw std::runtime_error("DeriveAppContainerSidFromAppContainerName: " 
                + HRESULT_CODE(result));
        }
    } else if (!SUCCEEDED(result)) {
        throw std::runtime_error("CreateAppContainerProfile: " + HRESULT_CODE(result));
    }

    scope_guard guard_sid = [&]() {
        ::FreeSid(sid);
    };

    const auto optJavaHome = EnvVar("JAVA_HOME");
    if (!optJavaHome) {
        throw std::runtime_error("No JAVA_HOME set");
    }
    const auto javaHome = optJavaHome.value();
    const auto javaBin = javaHome + R"(\bin\javaw.exe)";
    const auto workingDir = arguments.at(0);

    std::cout << "SID: " << SidToString(sid) << std::endl;
    std::cout << "JAVA_HOME: " << javaHome << std::endl;
    std::cout << "Working dir: " << workingDir << std::endl;

    // Allow read + execute from JAVA_HOME.
    GrantAccess(sid, javaHome, SE_FILE_OBJECT, FILE_EXECUTE | STANDARD_RIGHTS_READ);
    // Allow read + write for the working dir.
    GrantAccess(sid, workingDir, SE_FILE_OBJECT, FILE_ALL_ACCESS);
    
    SIZE_T attributeSize = 0;
    ::InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeSize);
    std::vector<uint8_t> buffer(attributeSize);

    auto startupInfo = std::make_unique<STARTUPINFOEXA>();
    startupInfo->lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer.data());
    scope_guard guard_lpAttributeList = [&]() {
        DeleteProcThreadAttributeList(startupInfo->lpAttributeList);
    };

    if (!::InitializeProcThreadAttributeList(
        startupInfo->lpAttributeList,
        1,
        NULL,
        &attributeSize)) {
        throw std::runtime_error("InitializeProcThreadAttributeList: " + GetLastError());
    }

    auto capabilities = std::make_unique<SECURITY_CAPABILITIES>();
    capabilities->Capabilities = nullptr;
    capabilities->CapabilityCount = 0;
    capabilities->AppContainerSid = sid;

    if (!::UpdateProcThreadAttribute(
        startupInfo->lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        capabilities.get(),
        sizeof(SECURITY_CAPABILITIES),
        nullptr,
        nullptr)) {
        throw std::runtime_error("UpdateProcThreadAttribute: " + GetLastError());
    }

    auto securityAttributes = std::make_unique<SECURITY_ATTRIBUTES>();
    securityAttributes->nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttributes->lpSecurityDescriptor = nullptr;
    securityAttributes->bInheritHandle = TRUE;

    HANDLE logHandle = CreateFileA(
        (workingDir + R"(\log.txt)").c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_WRITE | FILE_SHARE_READ,
        securityAttributes.get(),
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    scope_guard guard_logHandle = [&]() {
        CloseHandle(logHandle);
    };

    startupInfo->StartupInfo.hStdError = logHandle;
    startupInfo->StartupInfo.hStdOutput = logHandle;
    startupInfo->StartupInfo.dwFlags |= STARTF_USESTDHANDLES;

    auto processInfo = std::make_unique<PROCESS_INFORMATION>();
    scope_guard guard_processInfo = [&]() {
        CloseHandle(processInfo->hProcess);
        CloseHandle(processInfo->hThread);
    };

    if (!CreateProcessA(
        javaBin.c_str(),
        const_cast<LPSTR>(GetProcessArgs(arguments).c_str()),
        nullptr,
        nullptr,
        false, 
        EXTENDED_STARTUPINFO_PRESENT,
        nullptr, 
        workingDir.c_str(),
        (LPSTARTUPINFOA)startupInfo.get(),
        processInfo.get())) {
        throw std::runtime_error("CreateProcessA: " + GetLastError());
    }

    // TOOD wait for process to exit.
    return 0;
}

 
void GrantAccess(PSID sid, std::string objectName,
    SE_OBJECT_TYPE objectType, DWORD accessPermissions) {
    auto explicitAccess = std::make_unique<EXPLICIT_ACCESS_A>();
    explicitAccess->grfAccessMode = GRANT_ACCESS;
    explicitAccess->grfAccessPermissions = accessPermissions;
    explicitAccess->grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;

    explicitAccess->Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    explicitAccess->Trustee.pMultipleTrustee = nullptr;
    explicitAccess->Trustee.ptstrName = (CHAR*)sid;
    explicitAccess->Trustee.TrusteeForm = TRUSTEE_IS_SID;
    explicitAccess->Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;

    auto originalAcl = std::make_unique<PACL>();
    DWORD status = ::GetNamedSecurityInfoA(
        objectName.c_str(),
        objectType,
        DACL_SECURITY_INFORMATION,
        nullptr, 
        nullptr,
        originalAcl.get(),
        nullptr,
        nullptr);
    if (status != ERROR_SUCCESS) {
        throw std::runtime_error(std::format("GetNamedSecurityInfoA: {} : {}",
            objectName, status));
    }

    auto newAcl = std::make_unique<PACL>();
    status = ::SetEntriesInAclA(
        1,
        explicitAccess.get(),
        *originalAcl.get(),
        newAcl.get()
    );
    if (status != ERROR_SUCCESS) {
        throw std::runtime_error(std::format("SetEntriesInAclA: {} : {}",
            objectName, status));
    }

    status = ::SetNamedSecurityInfoA(
        const_cast<char*>(objectName.c_str()),
        objectType,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        *newAcl.get(),
        nullptr
    );
    if (status != ERROR_SUCCESS) {
        throw std::runtime_error(std::format("SetNamedSecurityInfoA: {} : {}",
            objectName, status));
    }
}

std::string SidToString(PSID sid) {
    auto stringSid = std::make_unique<LPSTR>();
    if (!::ConvertSidToStringSidA(sid, stringSid.get())) {
        throw std::runtime_error("Failed to convert SID to string.");
    }
    std::string result(*stringSid.get());
    return result;
}

std::optional<std::string> EnvVar(const std::string& key) {
    // Read the size of the env var
    DWORD size = ::GetEnvironmentVariableA(key.c_str(), nullptr, 0);
    if (!size || ::GetLastError() == ERROR_ENVVAR_NOT_FOUND) {
        return std::nullopt;
    }

    // Read the env var
    std::string value(size, L'\0');
    size = ::GetEnvironmentVariableA(key.c_str(), &value[0], size);
    if (!size || size >= value.size()) {
        return std::nullopt;
    }

    value.resize(size);
    return value;
}

std::string GetProcessArgs(const std::vector<std::string>& vec) {
    std::string result;
    // Start from the second entry
    for (size_t i = 1; i < vec.size(); ++i) {
        result += vec[i] + " ";
    }
    return result;
}

int main(int argc, char* argv[]) {
    try {
        run(argc, argv);
    } catch (const std::exception& e) {
        std::cout << "Uncaught exception: " << e.what() << std::endl;
    }
}
