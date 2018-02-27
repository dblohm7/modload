#include <windows.h>
#include <objbase.h>
#include <shobjidl.h>
#include <shellapi.h>

#include <memory>
#include <string>

#include <string.h>

#include <comdef.h>
#include <comip.h>

#pragma comment(lib, "shell32")

struct ArgvDeleter
{
  void operator()(LPWSTR* aPtr)
  {
    ::LocalFree(reinterpret_cast<void*>(aPtr));
  }
};

struct ComDeleter
{
  void operator()(void* aPtr)
  {
    ::CoTaskMemFree(aPtr);
  }
};

typedef std::unique_ptr<LPWSTR, ArgvDeleter> UniqueArgvPtr;
typedef std::unique_ptr<wchar_t, ComDeleter> UniqueComStringPtr;

static const wchar_t* kCmdLineSwitches[] {
  L"--modload-target-module",
  L"--modload-target-firefox"
};

_COM_SMARTPTR_TYPEDEF(IApplicationAssociationRegistration,
                      IID_IApplicationAssociationRegistration);

static bool
FindFirefox(std::wstring& aOutFirefoxPath)
{
  IApplicationAssociationRegistrationPtr appRegInfo;
  HRESULT hr = appRegInfo.CreateInstance(CLSID_ApplicationAssociationRegistration,
                                         nullptr, CLSCTX_INPROC_SERVER);
  if (FAILED(hr)) {
    return false;
  }

  LPWSTR rawProgId;
  hr = appRegInfo->QueryCurrentDefault(L"http", AT_URLPROTOCOL, AL_EFFECTIVE,
                                       &rawProgId);
  if (FAILED(hr)) {
    return false;
  }

  UniqueComStringPtr progId(rawProgId);
  aOutFirefoxPath = rawProgId;
  return true;
}

static bool
GetTargetModule(std::wstring& aOutTargetModule)
{
  return true;
}

static bool
GetBinaries(int aArgc, LPWSTR* aArgv, std::wstring& aOutFirefoxPath,
            std::wstring& aOutTargetModule)
{
  aOutFirefoxPath.clear();
  aOutTargetModule.clear();

  for (int i = 1; i < aArgc; ++i) {
    if (!wcscmp(aArgv[i], kCmdLineSwitches[0]) && (i + 1) < aArgc) {
      aOutTargetModule = aArgv[i + 1];
      ++i;
      continue;
    }

    if (!wcscmp(aArgv[i], kCmdLineSwitches[1]) && (i + 1) < aArgc) {
      aOutFirefoxPath = aArgv[i + 1];
      ++i;
      continue;
    }
  }

  bool success = true;

  if (aOutFirefoxPath.empty()) {
    success &= FindFirefox(aOutFirefoxPath);
  }

  if (aOutTargetModule.empty()) {
    success &= GetTargetModule(aOutTargetModule);
  }

  return success;
}

template <COINIT Type>
class COMRegion final
{
public:
  COMRegion()
    : mResult(::CoInitializeEx(nullptr, Type | COINIT_DISABLE_OLE1DDE))
  {
  }

  ~COMRegion()
  {
    if (FAILED(mResult)) {
      return;
    }

    ::CoUninitialize();
  }

  COMRegion(const COMRegion&) = delete;
  COMRegion(COMRegion&&) = delete;
  COMRegion& operator=(const COMRegion&) = delete;
  COMRegion& operator=(COMRegion&&) = delete;

private:
  HRESULT mResult;
};

typedef COMRegion<COINIT_APARTMENTTHREADED> STARegion;
typedef COMRegion<COINIT_MULTITHREADED> MTARegion;

int WINAPI
wWinMain(HINSTANCE aInstance, HINSTANCE aPrevInstance, PWSTR aCmdLine,
         int aCmdShow)
{
  int argc;
  UniqueArgvPtr argv(::CommandLineToArgvW(aCmdLine, &argc));
  if (!argv) {
    return 1;
  }

  STARegion sta;

  std::wstring targetModule;
  std::wstring firefoxBinary;
  if (!GetBinaries(argc, argv.get(), firefoxBinary, targetModule)) {
    return 2;
  }

  return 0;
}

