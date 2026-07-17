#define _WIN32_DCOM
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <wia.h>
#include <sti.h>
#include <objidl.h>
#include <propidl.h>
#include <comdef.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cwctype>
#include <filesystem>
#include <iostream>
#include <new>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#pragma comment(lib, "wiaguid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")

namespace fs = std::filesystem;

namespace {

constexpr const char* APP_NAME = "FS Legal Scanner Native WIA Bridge";
constexpr const char* APP_VERSION = "1.0-beta";
constexpr int DEFAULT_DPI = 300;
constexpr int MIN_DPI = 75;
constexpr int MAX_DPI = 1200;

bool g_debugEnabled = false;

void Debug(const std::string& message) {
    if (g_debugEnabled) {
        std::cerr << "DEBUG|" << message << std::endl;
    }
}

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) return {};

    int required = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr
    );

    if (required <= 0) return {};

    std::string result(static_cast<size_t>(required), '\0');
    WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        result.data(),
        required,
        nullptr,
        nullptr
    );
    return result;
}

std::string HResultHex(HRESULT hr) {
    std::ostringstream stream;
    stream << "0x" << std::hex << std::uppercase
           << static_cast<unsigned long>(hr);
    return stream.str();
}

std::string HResultMessage(HRESULT hr) {
    _com_error error(hr);
    const wchar_t* text = error.ErrorMessage();
    return text ? WideToUtf8(text) : "Unknown COM error";
}

void EmitError(
    const std::string& token,
    HRESULT hr,
    const std::string& detail = {}
) {
    std::cout << "ERROR|" << token << "|" << HResultHex(hr);
    if (!detail.empty()) std::cout << "|" << detail;
    std::cout << "|" << HResultMessage(hr) << std::endl;
}

void PrintHelp() {
    std::cout
        << "======================================================================\n"
        << APP_NAME << "\n"
        << "Version " << APP_VERSION << "\n"
        << "WIA ONLY - this executable does not implement TWAIN.\n"
        << "======================================================================\n\n"
        << "COMMANDS\n"
        << "  WiaScannerBridge.exe list [--debug]\n"
        << "  WiaScannerBridge.exe status <scannerIndex> [--debug]\n"
        << "  WiaScannerBridge.exe scan <outputFile> <scannerIndex> [dpi] [mode] [--debug]\n"
        << "  WiaScannerBridge.exe --help\n\n"
        << "SCAN OPTIONS\n"
        << "  outputFile     Full output path, normally ending in .jpg\n"
        << "  scannerIndex   One-based WIA device index returned by list\n"
        << "  dpi            75-1200; default 300\n"
        << "  mode           color | grayscale | bw; default grayscale\n"
        << "  --debug, -d    Detailed diagnostics on stderr\n\n"
        << "STDOUT PROTOCOL\n"
        << "  DEVICE|<index>|<name>|<status>|<device-id>|<raw-type>|<base-type>\n"
        << "  STATUS|DEVICE|CONNECTED\n"
        << "  STATUS|TRANSFER_STARTED|0\n"
        << "  STATUS|PROGRESS|<0-100>\n"
        << "  STATUS|HARDWARE|WARMING_UP\n"
        << "  STATUS|HARDWARE|SCANNING\n"
        << "  STATUS|TRANSFER_COMPLETE|100\n"
        << "  META|BIT_DEPTH|<value>\n"
        << "  META|COLOR_MODE|<value>\n"
        << "  SUCCESS|SCAN_COMPLETED|<absolute-path>\n"
        << "  ERROR|<token>|<HRESULT>|<detail>|<message>\n\n"
        << "EXAMPLES\n"
        << "  WiaScannerBridge.exe list --debug\n"
        << "  WiaScannerBridge.exe status 2 --debug\n"
        << "  WiaScannerBridge.exe scan \"C:\\temp\\top.jpg\" 2 300 grayscale --debug\n"
        << "======================================================================\n";
}

template <typename T>
void SafeRelease(T*& pointer) {
    if (pointer) {
        pointer->Release();
        pointer = nullptr;
    }
}

class ComApartment final {
public:
    ComApartment() : result_(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)) {}

    ~ComApartment() {
        if (SUCCEEDED(result_)) CoUninitialize();
    }

    HRESULT result() const { return result_; }

private:
    HRESULT result_;
};

struct DeviceRecord {
    int index = 0;
    std::wstring id;
    std::wstring name;
    LONG rawType = 0;
    LONG baseType = 0;
    LONG status = 0;
    bool hasStatus = false;
};

bool ReadProperty(
    IWiaPropertyStorage* storage,
    PROPID id,
    PROPVARIANT& value
) {
    if (!storage) return false;

    PROPSPEC spec{};
    spec.ulKind = PRSPEC_PROPID;
    spec.propid = id;

    PropVariantInit(&value);
    HRESULT hr = storage->ReadMultiple(1, &spec, &value);
    if (FAILED(hr)) {
        PropVariantClear(&value);
        return false;
    }
    return true;
}

std::wstring ReadStringProperty(IWiaPropertyStorage* storage, PROPID id) {
    PROPVARIANT value;
    if (!ReadProperty(storage, id, value)) return {};

    std::wstring result;
    if (value.vt == VT_BSTR && value.bstrVal) {
        result.assign(value.bstrVal, SysStringLen(value.bstrVal));
    } else if (value.vt == VT_LPWSTR && value.pwszVal) {
        result = value.pwszVal;
    }

    PropVariantClear(&value);
    return result;
}

bool ReadLongProperty(IWiaPropertyStorage* storage, PROPID id, LONG& output) {
    PROPVARIANT value;
    if (!ReadProperty(storage, id, value)) return false;

    bool valid = false;
    if (value.vt == VT_I4) {
        output = value.lVal;
        valid = true;
    } else if (value.vt == VT_UI4) {
        output = static_cast<LONG>(value.ulVal);
        valid = true;
    }

    PropVariantClear(&value);
    return valid;
}

HRESULT CreateDeviceManager(IWiaDevMgr** manager) {
    if (!manager) return E_POINTER;
    *manager = nullptr;

    return CoCreateInstance(
        CLSID_WiaDevMgr,
        nullptr,
        CLSCTX_LOCAL_SERVER,
        IID_IWiaDevMgr,
        reinterpret_cast<void**>(manager)
    );
}

std::string DeviceStatusText(const DeviceRecord& device) {
    if (!device.hasStatus) return "DETECTED";
    return device.status == 1 ? "ONLINE" : "DETECTED";
}

std::vector<DeviceRecord> EnumerateWiaDevices(IWiaDevMgr* manager) {
    std::vector<DeviceRecord> devices;
    if (!manager) return devices;

    IEnumWIA_DEV_INFO* enumerator = nullptr;
    HRESULT hr = manager->EnumDeviceInfo(WIA_DEVINFO_ENUM_LOCAL, &enumerator);
    if (FAILED(hr) || !enumerator) {
        Debug("EnumDeviceInfo failed: " + HResultHex(hr) + " " + HResultMessage(hr));
        return devices;
    }

    IWiaPropertyStorage* storage = nullptr;
    ULONG fetched = 0;
    int index = 1;

    while (enumerator->Next(1, &storage, &fetched) == S_OK) {
        DeviceRecord record;
        record.index = index++;
        record.id = ReadStringProperty(storage, WIA_DIP_DEV_ID);
        record.name = ReadStringProperty(storage, WIA_DIP_DEV_NAME);

        if (record.name.empty()) {
            record.name = ReadStringProperty(storage, WIA_DIP_DEV_DESC);
        }
        if (record.name.empty()) {
            record.name = L"WIA Device " + std::to_wstring(record.index);
        }

        if (ReadLongProperty(storage, WIA_DIP_DEV_TYPE, record.rawType)) {
            record.baseType = GET_STIDEVICE_TYPE(record.rawType);
        }

#ifdef WIA_DIP_DEV_STATUS
        record.hasStatus = ReadLongProperty(storage, WIA_DIP_DEV_STATUS, record.status);
#endif

        Debug(
            "Enumerated index=" + std::to_string(record.index) +
            " name=" + WideToUtf8(record.name) +
            " id=" + WideToUtf8(record.id) +
            " rawType=" + std::to_string(record.rawType) +
            " baseType=" + std::to_string(record.baseType)
        );

        // Compatibility-first behavior: retain every locally exposed WIA device.
        // Some multifunction scanner drivers report unexpected type information.
        devices.push_back(std::move(record));

        storage->Release();
        storage = nullptr;
    }

    SafeRelease(enumerator);
    Debug("Total WIA devices=" + std::to_string(devices.size()));
    return devices;
}

HRESULT CreateSelectedDevice(
    IWiaDevMgr* manager,
    int requestedIndex,
    IWiaItem** rootItem,
    DeviceRecord* selectedRecord = nullptr
) {
    if (!manager || !rootItem) return E_POINTER;
    *rootItem = nullptr;

    auto devices = EnumerateWiaDevices(manager);
    if (requestedIndex < 1 || requestedIndex > static_cast<int>(devices.size())) {
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    }

    const DeviceRecord& selected = devices[static_cast<size_t>(requestedIndex - 1)];
    if (selectedRecord) *selectedRecord = selected;
    if (selected.id.empty()) return E_FAIL;

    Debug(
        "Opening WIA device index=" + std::to_string(requestedIndex) +
        " name=" + WideToUtf8(selected.name) +
        " id=" + WideToUtf8(selected.id)
    );

    BSTR deviceId = SysAllocString(selected.id.c_str());
    if (!deviceId) return E_OUTOFMEMORY;

    HRESULT hr = manager->CreateDevice(deviceId, rootItem);
    SysFreeString(deviceId);

    Debug(
        std::string("CreateDevice ") +
        (SUCCEEDED(hr) ? "succeeded" : "failed") +
        " hr=" + HResultHex(hr)
    );
    return hr;
}

HRESULT GetFirstTransferItem(IWiaItem* root, IWiaItem** scanItem) {
    if (!root || !scanItem) return E_POINTER;
    *scanItem = nullptr;

    IEnumWiaItem* enumerator = nullptr;
    HRESULT hr = root->EnumChildItems(&enumerator);

    if (SUCCEEDED(hr) && enumerator) {
        ULONG fetched = 0;
        hr = enumerator->Next(1, scanItem, &fetched);
        enumerator->Release();

        if (hr == S_OK && *scanItem) {
            Debug("Using first child WIA transfer item.");
            return S_OK;
        }
    }

    root->AddRef();
    *scanItem = root;
    Debug("No child item returned; using WIA root item.");
    return S_OK;
}

LONG ParseColorMode(const std::string& requestedMode) {
    std::string mode = requestedMode;
    std::transform(
        mode.begin(),
        mode.end(),
        mode.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); }
    );

    if (mode == "color" || mode == "colour") return WIA_DATA_COLOR;
    if (mode == "bw" || mode == "blackwhite" || mode == "threshold") {
        return WIA_DATA_THRESHOLD;
    }
    return WIA_DATA_GRAYSCALE;
}

LONG DepthForDataType(LONG dataType) {
    if (dataType == WIA_DATA_COLOR) return 24;
    if (dataType == WIA_DATA_THRESHOLD) return 1;
    return 8;
}

HRESULT WriteLongProperty(
    IWiaPropertyStorage* storage,
    PROPID id,
    LONG value
) {
    if (!storage) return E_POINTER;

    PROPSPEC spec{};
    spec.ulKind = PRSPEC_PROPID;
    spec.propid = id;

    PROPVARIANT variant;
    PropVariantInit(&variant);
    variant.vt = VT_I4;
    variant.lVal = value;

    HRESULT hr = storage->WriteMultiple(1, &spec, &variant, WIA_IPA_FIRST);
    PropVariantClear(&variant);
    return hr;
}

HRESULT WriteGuidProperty(
    IWiaPropertyStorage* storage,
    PROPID id,
    const GUID& value
) {
    if (!storage) return E_POINTER;

    PROPSPEC spec{};
    spec.ulKind = PRSPEC_PROPID;
    spec.propid = id;

    GUID localValue = value;
    PROPVARIANT variant;
    PropVariantInit(&variant);
    variant.vt = VT_CLSID;
    variant.puuid = &localValue;

    HRESULT hr = storage->WriteMultiple(1, &spec, &variant, WIA_IPA_FIRST);

    // Prevent PropVariantClear from freeing a stack GUID.
    variant.vt = VT_EMPTY;
    variant.puuid = nullptr;
    return hr;
}

HRESULT ConfigureScanItem(IWiaItem* item, int dpi, LONG dataType) {
    if (!item) return E_POINTER;

    IWiaPropertyStorage* storage = nullptr;
    HRESULT hr = item->QueryInterface(
        IID_IWiaPropertyStorage,
        reinterpret_cast<void**>(&storage)
    );
    if (FAILED(hr) || !storage) return hr;

    HRESULT firstFailure = S_OK;

    auto writeLong = [&](PROPID id, LONG value, const char* label) {
        HRESULT writeHr = WriteLongProperty(storage, id, value);
        Debug(
            std::string("Set ") + label + "=" + std::to_string(value) +
            " hr=" + HResultHex(writeHr)
        );
        if (FAILED(writeHr) && SUCCEEDED(firstFailure)) firstFailure = writeHr;
    };

    writeLong(WIA_IPS_XRES, dpi, "WIA_IPS_XRES");
    writeLong(WIA_IPS_YRES, dpi, "WIA_IPS_YRES");
    writeLong(WIA_IPA_DATATYPE, dataType, "WIA_IPA_DATATYPE");
    writeLong(WIA_IPA_DEPTH, DepthForDataType(dataType), "WIA_IPA_DEPTH");
    writeLong(WIA_IPA_TYMED, TYMED_FILE, "WIA_IPA_TYMED");

    HRESULT formatHr = WriteGuidProperty(storage, WIA_IPA_FORMAT, WiaImgFmt_JPEG);
    Debug("Set WIA_IPA_FORMAT=JPEG hr=" + HResultHex(formatHr));
    if (FAILED(formatHr)) {
        std::cout << "WARNING|FORMAT_NOT_SET|" << HResultHex(formatHr) << std::endl;
    }

    storage->Release();
    return firstFailure;
}

void EmitItemMetadata(IWiaItem* item) {
    if (!item) return;

    IWiaPropertyStorage* storage = nullptr;
    HRESULT hr = item->QueryInterface(
        IID_IWiaPropertyStorage,
        reinterpret_cast<void**>(&storage)
    );
    if (FAILED(hr) || !storage) return;

    LONG depth = 0;
    if (ReadLongProperty(storage, WIA_IPA_DEPTH, depth)) {
        std::cout << "META|BIT_DEPTH|" << depth << std::endl;
    }

    LONG dataType = 0;
    if (ReadLongProperty(storage, WIA_IPA_DATATYPE, dataType)) {
        std::string mode = "Unknown";
        if (dataType == WIA_DATA_COLOR) mode = "Color";
        else if (dataType == WIA_DATA_GRAYSCALE) mode = "Grayscale";
        else if (dataType == WIA_DATA_THRESHOLD) mode = "BlackAndWhite";
        std::cout << "META|COLOR_MODE|" << mode << std::endl;
    }

#ifdef WIA_DPS_DOCUMENT_HANDLING_STATUS
    LONG handlingStatus = 0;
    if (ReadLongProperty(storage, WIA_DPS_DOCUMENT_HANDLING_STATUS, handlingStatus)) {
#ifdef PAPER_JAM
        if (handlingStatus & PAPER_JAM) {
            std::cout << "META|FEEDER|PAPER_JAM" << std::endl;
        } else
#endif
#ifdef FEED_READY
        if (handlingStatus & FEED_READY) {
            std::cout << "META|FEEDER|READY" << std::endl;
        } else
#endif
        {
            std::cout << "META|FEEDER|AVAILABLE" << std::endl;
        }
    }
#endif

    storage->Release();
}

class AsyncScanCallback final : public IWiaDataCallback {
public:
    AsyncScanCallback() : referenceCount_(1), lastPercent_(-1) {}

    STDMETHODIMP QueryInterface(REFIID riid, void** object) override {
        if (!object) return E_POINTER;

        if (riid == IID_IUnknown || riid == IID_IWiaDataCallback) {
            *object = static_cast<IWiaDataCallback*>(this);
            AddRef();
            return S_OK;
        }

        *object = nullptr;
        return E_NOINTERFACE;
    }

    STDMETHODIMP_(ULONG) AddRef() override {
        return static_cast<ULONG>(InterlockedIncrement(&referenceCount_));
    }

    STDMETHODIMP_(ULONG) Release() override {
        LONG remaining = InterlockedDecrement(&referenceCount_);
        if (remaining == 0) delete this;
        return static_cast<ULONG>(remaining);
    }

    STDMETHODIMP BandedDataCallback(
        LONG message,
        LONG status,
        LONG percentComplete,
        LONG,
        LONG,
        LONG,
        LONG,
        BYTE*
    ) override {
        switch (message) {
        case IT_MSG_DATA_HEADER:
            std::cout << "STATUS|TRANSFER_STARTED|0" << std::endl;
            break;

        case IT_MSG_DATA:
            EmitProgress(percentComplete);
            break;

        case IT_MSG_STATUS:
#ifdef WIA_STATUS_WARMING_UP
            if (status & WIA_STATUS_WARMING_UP) {
                std::cout << "STATUS|HARDWARE|WARMING_UP" << std::endl;
            }
#endif
#ifdef WIA_STATUS_SCANNING
            if (status & WIA_STATUS_SCANNING) {
                std::cout << "STATUS|HARDWARE|SCANNING" << std::endl;
            }
#endif
            break;

        case IT_MSG_NEW_PAGE:
            std::cout << "STATUS|HARDWARE|NEW_PAGE" << std::endl;
            break;

        case IT_MSG_TERMINATION:
            EmitProgress(100);
            std::cout << "STATUS|TRANSFER_COMPLETE|100" << std::endl;
            break;
        }

        return S_OK;
    }

private:
    void EmitProgress(LONG percent) {
        percent = std::clamp<LONG>(percent, 0, 100);
        LONG previous = lastPercent_.exchange(percent);
        if (previous != percent) {
            std::cout << "STATUS|PROGRESS|" << percent << std::endl;
        }
    }

    volatile LONG referenceCount_;
    std::atomic<LONG> lastPercent_;
};

HRESULT TransferToFile(IWiaItem* item, const fs::path& requestedDestination) {
    if (!item) return E_POINTER;

    IWiaDataTransfer* transfer = nullptr;
    HRESULT hr = item->QueryInterface(
        IID_IWiaDataTransfer,
        reinterpret_cast<void**>(&transfer)
    );
    if (FAILED(hr) || !transfer) return hr;

    STGMEDIUM medium{};
    medium.tymed = TYMED_FILE;
    medium.lpszFileName = nullptr;
    medium.pUnkForRelease = nullptr;

    auto* callback = new (std::nothrow) AsyncScanCallback();
    if (!callback) {
        transfer->Release();
        return E_OUTOFMEMORY;
    }

    Debug("Calling IWiaDataTransfer::idtGetData.");
    hr = transfer->idtGetData(&medium, callback);
    callback->Release();
    transfer->Release();

    Debug("idtGetData returned hr=" + HResultHex(hr));

    if (FAILED(hr)) {
        if (medium.tymed != TYMED_NULL) ReleaseStgMedium(&medium);
        return hr;
    }

    if (medium.tymed != TYMED_FILE || !medium.lpszFileName) {
        if (medium.tymed != TYMED_NULL) ReleaseStgMedium(&medium);
        return E_FAIL;
    }

    fs::path temporaryFile(medium.lpszFileName);
    Debug("WIA temporary file=" + WideToUtf8(temporaryFile.wstring()));

    std::error_code error;
    fs::path destination = fs::absolute(requestedDestination, error);
    if (error) {
        error.clear();
        destination = requestedDestination;
    }

    if (destination.has_parent_path()) {
        fs::create_directories(destination.parent_path(), error);
        if (error) {
            HRESULT directoryHr = HRESULT_FROM_WIN32(error.value());
            ReleaseStgMedium(&medium);
            return directoryHr;
        }
    }

    fs::copy_file(
        temporaryFile,
        destination,
        fs::copy_options::overwrite_existing,
        error
    );

    ReleaseStgMedium(&medium);

    if (error) return HRESULT_FROM_WIN32(error.value());
    if (!fs::exists(destination) || fs::file_size(destination, error) == 0) return E_FAIL;

    std::cout << "SUCCESS|SCAN_COMPLETED|"
              << WideToUtf8(destination.wstring()) << std::endl;
    return S_OK;
}

bool IsDebugFlag(const std::wstring& argument) {
    std::wstring lower = argument;
    std::transform(
        lower.begin(),
        lower.end(),
        lower.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); }
    );
    return lower == L"--debug" || lower == L"-d";
}

bool HasDebugFlag(int argc, wchar_t* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (IsDebugFlag(argv[i])) return true;
    }
    return false;
}

std::vector<std::wstring> PositionalArguments(int argc, wchar_t* argv[]) {
    std::vector<std::wstring> result;
    for (int i = 1; i < argc; ++i) {
        if (!IsDebugFlag(argv[i])) result.emplace_back(argv[i]);
    }
    return result;
}

int ParseInteger(const std::wstring& text, int fallback) {
    try {
        size_t consumed = 0;
        int value = std::stoi(text, &consumed);
        return consumed == text.size() ? value : fallback;
    } catch (...) {
        return fallback;
    }
}

int CommandList(IWiaDevMgr* manager) {
    auto devices = EnumerateWiaDevices(manager);

    if (devices.empty()) {
        std::cout << "NO_SCANNER" << std::endl;
        return 2;
    }

    for (const auto& device : devices) {
        std::cout << "DEVICE|"
                  << device.index << "|"
                  << WideToUtf8(device.name) << "|"
                  << DeviceStatusText(device) << "|"
                  << WideToUtf8(device.id) << "|"
                  << device.rawType << "|"
                  << device.baseType
                  << std::endl;
    }

    return 0;
}

int CommandStatus(IWiaDevMgr* manager, int index) {
    IWiaItem* root = nullptr;
    DeviceRecord selected;
    HRESULT hr = CreateSelectedDevice(manager, index, &root, &selected);

    if (FAILED(hr) || !root) {
        EmitError("DEVICE_UNAVAILABLE", hr, "WIA index " + std::to_string(index));
        return 3;
    }

    std::cout << "STATUS|DEVICE|CONNECTED" << std::endl;
    std::cout << "META|DEVICE_INDEX|" << selected.index << std::endl;
    std::cout << "META|DEVICE_NAME|" << WideToUtf8(selected.name) << std::endl;
    std::cout << "META|DEVICE_ID|" << WideToUtf8(selected.id) << std::endl;
    std::cout << "META|RAW_DEVICE_TYPE|" << selected.rawType << std::endl;
    std::cout << "META|BASE_DEVICE_TYPE|" << selected.baseType << std::endl;

    SafeRelease(root);
    return 0;
}

int CommandScan(
    IWiaDevMgr* manager,
    const fs::path& output,
    int index,
    int dpi,
    const std::string& requestedMode
) {
    dpi = std::clamp(dpi, MIN_DPI, MAX_DPI);
    LONG dataType = ParseColorMode(requestedMode);

    Debug(
        "Scan request output=" + WideToUtf8(output.wstring()) +
        " index=" + std::to_string(index) +
        " dpi=" + std::to_string(dpi) +
        " mode=" + requestedMode
    );

    IWiaItem* root = nullptr;
    DeviceRecord selected;
    HRESULT hr = CreateSelectedDevice(manager, index, &root, &selected);

    if (FAILED(hr) || !root) {
        EmitError("DEVICE_UNAVAILABLE", hr, "WIA index " + std::to_string(index));
        return 3;
    }

    std::cout << "STATUS|DEVICE|CONNECTED" << std::endl;
    std::cout << "META|DEVICE_NAME|" << WideToUtf8(selected.name) << std::endl;
    std::cout << "META|DEVICE_ID|" << WideToUtf8(selected.id) << std::endl;
    std::cout << "META|REQUESTED_DPI|" << dpi << std::endl;

    IWiaItem* scanItem = nullptr;
    hr = GetFirstTransferItem(root, &scanItem);
    if (FAILED(hr) || !scanItem) {
        EmitError("SCAN_ITEM_UNAVAILABLE", hr);
        SafeRelease(root);
        return 4;
    }

    hr = ConfigureScanItem(scanItem, dpi, dataType);
    if (FAILED(hr)) {
        std::cout << "WARNING|SETTINGS_PARTIAL|" << HResultHex(hr) << std::endl;
    }

    EmitItemMetadata(scanItem);
    hr = TransferToFile(scanItem, output);

    SafeRelease(scanItem);
    SafeRelease(root);

    if (FAILED(hr)) {
        EmitError("TRANSFER_FAILED", hr);
        return 5;
    }

    return 0;
}

} // namespace

int wmain(int argc, wchar_t* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    g_debugEnabled = HasDebugFlag(argc, argv);
    auto arguments = PositionalArguments(argc, argv);

    if (g_debugEnabled) {
        Debug(std::string(APP_NAME) + " " + APP_VERSION);
        Debug("Debug output is on stderr; protocol output is on stdout.");
    }

    if (arguments.empty()) {
        PrintHelp();
        return 0;
    }

    std::wstring command = arguments[0];
    std::transform(
        command.begin(),
        command.end(),
        command.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); }
    );

    if (command == L"--help" || command == L"-h" || command == L"/?") {
        PrintHelp();
        return 0;
    }

    ComApartment apartment;
    if (FAILED(apartment.result())) {
        EmitError("COM_INITIALIZATION_FAILED", apartment.result());
        return 1;
    }

    IWiaDevMgr* manager = nullptr;
    HRESULT hr = CreateDeviceManager(&manager);
    if (FAILED(hr) || !manager) {
        EmitError("WIA_MANAGER_UNAVAILABLE", hr);
        return 1;
    }

    int result = 0;

    if (command == L"list") {
        result = CommandList(manager);
    } else if (command == L"status") {
        if (arguments.size() < 2) {
            std::cout << "ERROR|MISSING_SCANNER_INDEX" << std::endl;
            result = 64;
        } else {
            result = CommandStatus(manager, ParseInteger(arguments[1], 1));
        }
    } else if (command == L"scan") {
        if (arguments.size() < 3) {
            std::cout
                << "ERROR|INVALID_ARGUMENTS|Expected: scan <file> <index> [dpi] [mode]"
                << std::endl;
            result = 64;
        } else {
            fs::path output(arguments[1]);
            int index = ParseInteger(arguments[2], 1);
            int dpi = arguments.size() >= 4
                ? ParseInteger(arguments[3], DEFAULT_DPI)
                : DEFAULT_DPI;
            std::string mode = arguments.size() >= 5
                ? WideToUtf8(arguments[4])
                : "grayscale";

            result = CommandScan(manager, output, index, dpi, mode);
        }
    } else {
        std::cout << "ERROR|UNKNOWN_COMMAND|" << WideToUtf8(command) << std::endl;
        PrintHelp();
        result = 64;
    }

    SafeRelease(manager);
    return result;
}
