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
#include <filesystem>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "wiaguid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")

namespace fs = std::filesystem;

namespace {

constexpr int DEFAULT_DPI = 300;
constexpr int MIN_DPI = 75;
constexpr int MAX_DPI = 1200;

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) return {};

    int size = WideCharToMultiByte(
        CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr
    );

    if (size <= 0) return {};

    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()),
        result.data(), size, nullptr, nullptr
    );
    return result;
}

std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) return {};

    int size = MultiByteToWideChar(
        CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()),
        nullptr, 0
    );

    if (size <= 0) return {};

    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()),
        result.data(), size
    );
    return result;
}

std::string HrHex(HRESULT hr) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase
        << static_cast<unsigned long>(hr);
    return out.str();
}

std::string HrMessage(HRESULT hr) {
    _com_error error(hr);
    const wchar_t* message = error.ErrorMessage();
    return message ? WideToUtf8(message) : "Unknown COM error";
}

void EmitError(const std::string& token, HRESULT hr, const std::string& detail = {}) {
    std::cout << "ERROR|" << token << "|" << HrHex(hr);
    if (!detail.empty()) std::cout << "|" << detail;
    std::cout << "|" << HrMessage(hr) << std::endl;
}

void PrintHelpManual() {
    std::cout
        << "======================================================================\n"
        << "FS LEGAL SCANNER - NATIVE WIA BRIDGE\n"
        << "Version 1.0-beta\n"
        << "======================================================================\n\n"
        << "COMMANDS\n"
        << "  WiaScannerBridge.exe list\n"
        << "  WiaScannerBridge.exe status <scannerIndex>\n"
        << "  WiaScannerBridge.exe scan <outputFile> <scannerIndex> [dpi] [mode]\n"
        << "  WiaScannerBridge.exe --help\n\n"
        << "SCAN OPTIONS\n"
        << "  outputFile     Full destination path, normally ending in .jpg\n"
        << "  scannerIndex   One-based index returned by the list command\n"
        << "  dpi            75-1200; default 300\n"
        << "  mode           color | grayscale | bw; default grayscale\n\n"
        << "STDOUT PROTOCOL\n"
        << "  <index>|<scanner-name>|<status>\n"
        << "  STATUS|TRANSFER_STARTED|0\n"
        << "  STATUS|PROGRESS|<0-100>\n"
        << "  STATUS|HARDWARE|WARMING_UP\n"
        << "  STATUS|HARDWARE|SCANNING\n"
        << "  STATUS|TRANSFER_COMPLETE|100\n"
        << "  META|BIT_DEPTH|<value>\n"
        << "  META|COLOR_MODE|<value>\n"
        << "  SUCCESS|SCAN_COMPLETED|<absolute-path>\n"
        << "  ERROR|<token>|<HRESULT>|<detail>\n"
        << "======================================================================\n";
}

template <typename T>
void SafeRelease(T*& value) {
    if (value) {
        value->Release();
        value = nullptr;
    }
}

class ComApartment {
public:
    ComApartment() : hr_(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)) {}
    ~ComApartment() {
        if (SUCCEEDED(hr_)) CoUninitialize();
    }
    HRESULT result() const { return hr_; }

private:
    HRESULT hr_;
};

struct DeviceRecord {
    int index = 0;
    std::wstring id;
    std::wstring name;
    LONG type = 0;
    LONG status = 0;
    bool hasStatus = false;
};

bool ReadProperty(
    IWiaPropertyStorage* storage,
    PROPID propertyId,
    PROPVARIANT& value
) {
    if (!storage) return false;

    PROPSPEC spec{};
    spec.ulKind = PRSPEC_PROPID;
    spec.propid = propertyId;

    PropVariantInit(&value);
    HRESULT hr = storage->ReadMultiple(1, &spec, &value);
    return SUCCEEDED(hr);
}

std::wstring ReadStringProperty(IWiaPropertyStorage* storage, PROPID propertyId) {
    PROPVARIANT value;
    if (!ReadProperty(storage, propertyId, value)) return {};

    std::wstring result;
    if (value.vt == VT_BSTR && value.bstrVal) {
        result.assign(value.bstrVal, SysStringLen(value.bstrVal));
    } else if (value.vt == VT_LPWSTR && value.pwszVal) {
        result = value.pwszVal;
    }

    PropVariantClear(&value);
    return result;
}

bool ReadLongProperty(
    IWiaPropertyStorage* storage,
    PROPID propertyId,
    LONG& result
) {
    PROPVARIANT value;
    if (!ReadProperty(storage, propertyId, value)) return false;

    bool ok = false;
    if (value.vt == VT_I4) {
        result = value.lVal;
        ok = true;
    } else if (value.vt == VT_UI4) {
        result = static_cast<LONG>(value.ulVal);
        ok = true;
    }

    PropVariantClear(&value);
    return ok;
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

std::vector<DeviceRecord> EnumerateScanners(IWiaDevMgr* manager) {
    std::vector<DeviceRecord> devices;
    if (!manager) return devices;

    IEnumWIA_DEV_INFO* enumerator = nullptr;
    HRESULT hr = manager->EnumDeviceInfo(WIA_DEVINFO_ENUM_LOCAL, &enumerator);
    if (FAILED(hr) || !enumerator) return devices;

    IWiaPropertyStorage* storage = nullptr;
    ULONG fetched = 0;
    int index = 1;

    while (enumerator->Next(1, &storage, &fetched) == S_OK) {
        DeviceRecord record;
        record.index = index++;
        record.id = ReadStringProperty(storage, WIA_DIP_DEV_ID);
        record.name = ReadStringProperty(storage, WIA_DIP_DEV_NAME);

        if (record.name.empty()) {
            record.name = L"Scanner " + std::to_wstring(record.index);
        }

        ReadLongProperty(storage, WIA_DIP_DEV_TYPE, record.type);

#ifdef WIA_DIP_DEV_STATUS
        record.hasStatus = ReadLongProperty(storage, WIA_DIP_DEV_STATUS, record.status);
#endif

        // WIA_DEVINFO_ENUM_LOCAL can expose non-scanner WIA devices.
        // Keep only scanner devices when the type property is available.
        if (record.type == 0 || record.type == StiDeviceTypeScanner) {
            devices.push_back(std::move(record));
        }

        storage->Release();
        storage = nullptr;
    }

    SafeRelease(enumerator);

    // Re-number after filtering so Java receives contiguous one-based indices.
    for (size_t i = 0; i < devices.size(); ++i) {
        devices[i].index = static_cast<int>(i + 1);
    }

    return devices;
}

std::string DeviceStatusText(const DeviceRecord& device) {
    // Device status is optional and driver-dependent. Enumeration itself confirms
    // that the device is currently exposed by WIA.
    if (!device.hasStatus) return "DETECTED";
    return device.status == 1 ? "ONLINE" : "DETECTED";
}

HRESULT CreateSelectedDevice(
    IWiaDevMgr* manager,
    int oneBasedIndex,
    IWiaItem** rootItem,
    DeviceRecord* selectedRecord = nullptr
) {
    if (!manager || !rootItem) return E_POINTER;
    *rootItem = nullptr;

    auto devices = EnumerateScanners(manager);
    if (oneBasedIndex < 1 || oneBasedIndex > static_cast<int>(devices.size())) {
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    }

    const DeviceRecord& device = devices[static_cast<size_t>(oneBasedIndex - 1)];
    if (selectedRecord) *selectedRecord = device;

    if (device.id.empty()) return E_FAIL;

    return manager->CreateDevice(
        const_cast<BSTR>(device.id.c_str()),
        rootItem
    );
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

        if (hr == S_OK && *scanItem) return S_OK;
    }

    // Some drivers expose transfer directly through the root item.
    root->AddRef();
    *scanItem = root;
    return S_OK;
}

LONG ParseColorMode(const std::string& mode) {
    std::string lower = mode;
    std::transform(lower.begin(), lower.end(), lower.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (lower == "color" || lower == "colour") return WIA_DATA_COLOR;
    if (lower == "bw" || lower == "blackwhite" || lower == "threshold") {
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
    PROPSPEC spec{};
    spec.ulKind = PRSPEC_PROPID;
    spec.propid = id;

    GUID copy = value;
    PROPVARIANT variant;
    PropVariantInit(&variant);
    variant.vt = VT_CLSID;
    variant.puuid = &copy;

    // WriteMultiple consumes the value during the call; the stack GUID remains valid.
    HRESULT hr = storage->WriteMultiple(1, &spec, &variant, WIA_IPA_FIRST);
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

    // Some drivers reject individual optional properties. X/Y resolution and
    // datatype are the important settings; format/tymed are attempted safely.
    HRESULT firstFailure = S_OK;

    auto tryWriteLong = [&](PROPID id, LONG value) {
        HRESULT writeHr = WriteLongProperty(storage, id, value);
        if (FAILED(writeHr) && SUCCEEDED(firstFailure)) firstFailure = writeHr;
    };

    tryWriteLong(WIA_IPS_XRES, dpi);
    tryWriteLong(WIA_IPS_YRES, dpi);
    tryWriteLong(WIA_IPA_DATATYPE, dataType);
    tryWriteLong(WIA_IPA_DEPTH, DepthForDataType(dataType));
    tryWriteLong(WIA_IPA_TYMED, TYMED_FILE);

    HRESULT formatHr = WriteGuidProperty(storage, WIA_IPA_FORMAT, WiaImgFmt_JPEG);
    if (FAILED(formatHr)) {
        // JPEG is preferred because the Java workflow currently uses .jpg files.
        // A driver is permitted to reject it; transfer may still succeed using
        // the driver's current format.
        std::cout << "WARNING|FORMAT_NOT_SET|" << HrHex(formatHr) << std::endl;
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

    LONG datatype = 0;
    if (ReadLongProperty(storage, WIA_IPA_DATATYPE, datatype)) {
        std::string mode = "Unknown";
        if (datatype == WIA_DATA_COLOR) mode = "Color";
        else if (datatype == WIA_DATA_GRAYSCALE) mode = "Grayscale";
        else if (datatype == WIA_DATA_THRESHOLD) mode = "BlackAndWhite";
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
    AsyncScanCallback() : refCount_(1), lastPercent_(-1) {}

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
        return static_cast<ULONG>(InterlockedIncrement(&refCount_));
    }

    STDMETHODIMP_(ULONG) Release() override {
        LONG remaining = InterlockedDecrement(&refCount_);
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

        case IT_MSG_TERMINATION:
            EmitProgress(100);
            std::cout << "STATUS|TRANSFER_COMPLETE|100" << std::endl;
            break;

        case IT_MSG_NEW_PAGE:
            std::cout << "STATUS|HARDWARE|NEW_PAGE" << std::endl;
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

    volatile LONG refCount_;
    std::atomic<LONG> lastPercent_;
};

HRESULT TransferToFile(IWiaItem* item, const fs::path& destination) {
    if (!item) return E_POINTER;

    IWiaDataTransfer* transfer = nullptr;
    HRESULT hr = item->QueryInterface(
        IID_IWiaDataTransfer,
        reinterpret_cast<void**>(&transfer)
    );
    if (FAILED(hr) || !transfer) return hr;

    STGMEDIUM medium{};
    medium.tymed = TYMED_FILE;
    medium.lpszFileName = nullptr; // WIA creates a temporary transfer file.
    medium.pUnkForRelease = nullptr;

    auto* callback = new (std::nothrow) AsyncScanCallback();
    if (!callback) {
        transfer->Release();
        return E_OUTOFMEMORY;
    }

    hr = transfer->idtGetData(&medium, callback);
    callback->Release();
    transfer->Release();

    if (FAILED(hr)) {
        if (medium.tymed != TYMED_NULL) ReleaseStgMedium(&medium);
        return hr;
    }

    if (medium.tymed != TYMED_FILE || !medium.lpszFileName) {
        if (medium.tymed != TYMED_NULL) ReleaseStgMedium(&medium);
        return E_FAIL;
    }

    fs::path temporaryFile(medium.lpszFileName);

    std::error_code error;
    fs::path absoluteDestination = fs::absolute(destination, error);
    if (error) absoluteDestination = destination;

    if (absoluteDestination.has_parent_path()) {
        fs::create_directories(absoluteDestination.parent_path(), error);
        if (error) {
            ReleaseStgMedium(&medium);
            return HRESULT_FROM_WIN32(error.value());
        }
    }

    fs::copy_file(
        temporaryFile,
        absoluteDestination,
        fs::copy_options::overwrite_existing,
        error
    );

    // The WIA-created temporary file is owned by STGMEDIUM and is removed by
    // ReleaseStgMedium, so copy it before releasing the medium.
    ReleaseStgMedium(&medium);

    if (error) return HRESULT_FROM_WIN32(error.value());
    if (!fs::exists(absoluteDestination)) return E_FAIL;

    std::cout << "SUCCESS|SCAN_COMPLETED|"
              << WideToUtf8(absoluteDestination.wstring()) << std::endl;
    return S_OK;
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
    auto devices = EnumerateScanners(manager);
    if (devices.empty()) {
        std::cout << "NO_SCANNER" << std::endl;
        return 2;
    }

    for (const auto& device : devices) {
        std::cout << device.index << "|"
                  << WideToUtf8(device.name) << "|"
                  << DeviceStatusText(device) << std::endl;
    }
    return 0;
}

int CommandStatus(IWiaDevMgr* manager, int index) {
    IWiaItem* root = nullptr;
    DeviceRecord selected;
    HRESULT hr = CreateSelectedDevice(manager, index, &root, &selected);

    if (FAILED(hr) || !root) {
        EmitError("DEVICE_UNAVAILABLE", hr, "Scanner index " + std::to_string(index));
        return 3;
    }

    std::cout << "STATUS|DEVICE|CONNECTED" << std::endl;
    std::cout << "META|DEVICE_INDEX|" << selected.index << std::endl;
    std::cout << "META|DEVICE_NAME|" << WideToUtf8(selected.name) << std::endl;
    SafeRelease(root);
    return 0;
}

int CommandScan(
    IWiaDevMgr* manager,
    const fs::path& output,
    int index,
    int dpi,
    const std::string& mode
) {
    dpi = std::clamp(dpi, MIN_DPI, MAX_DPI);
    LONG datatype = ParseColorMode(mode);

    IWiaItem* root = nullptr;
    DeviceRecord selected;
    HRESULT hr = CreateSelectedDevice(manager, index, &root, &selected);

    if (FAILED(hr) || !root) {
        EmitError("DEVICE_UNAVAILABLE", hr, "Scanner index " + std::to_string(index));
        return 3;
    }

    std::cout << "STATUS|DEVICE|CONNECTED" << std::endl;
    std::cout << "META|DEVICE_NAME|" << WideToUtf8(selected.name) << std::endl;
    std::cout << "META|REQUESTED_DPI|" << dpi << std::endl;

    IWiaItem* scanItem = nullptr;
    hr = GetFirstTransferItem(root, &scanItem);
    if (FAILED(hr) || !scanItem) {
        EmitError("SCAN_ITEM_UNAVAILABLE", hr);
        SafeRelease(root);
        return 4;
    }

    hr = ConfigureScanItem(scanItem, dpi, datatype);
    if (FAILED(hr)) {
        // Drivers vary widely; report the settings issue, but still attempt the
        // transfer because the current driver defaults may be usable.
        std::cout << "WARNING|SETTINGS_PARTIAL|" << HrHex(hr) << std::endl;
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

    if (argc < 2) {
        PrintHelpManual();
        return 0;
    }

    std::wstring command = argv[1];
    std::transform(command.begin(), command.end(), command.begin(), towlower);

    if (command == L"--help" || command == L"-h" || command == L"/?") {
        PrintHelpManual();
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
        if (argc < 3) {
            std::cout << "ERROR|MISSING_SCANNER_INDEX" << std::endl;
            result = 64;
        } else {
            result = CommandStatus(manager, ParseInteger(argv[2], 1));
        }
    } else if (command == L"scan") {
        if (argc < 4) {
            std::cout << "ERROR|INVALID_ARGUMENTS|Expected: scan <file> <index> [dpi] [mode]"
                      << std::endl;
            result = 64;
        } else {
            fs::path output(argv[2]);
            int index = ParseInteger(argv[3], 1);
            int dpi = argc >= 5 ? ParseInteger(argv[4], DEFAULT_DPI) : DEFAULT_DPI;
            std::string mode = argc >= 6 ? WideToUtf8(argv[5]) : "grayscale";
            result = CommandScan(manager, output, index, dpi, mode);
        }
    } else {
        std::cout << "ERROR|UNKNOWN_COMMAND|" << WideToUtf8(command) << std::endl;
        PrintHelpManual();
        result = 64;
    }

    SafeRelease(manager);
    return result;
}
