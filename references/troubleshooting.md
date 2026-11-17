# Troubleshooting

## Ghidra

| Triệu chứng | Nguyên nhân | Xử lý |
|---|---|---|
| Treo / OOM khi import | Heap mặc định 2 GB | `GHIDRA_HEADLESS_MAXMEM=16G` (script đã đặt; máy 16 GB RAM → `10G`) |
| `analyzeHeadless` không có trong PATH | Homebrew không tạo lệnh này | `/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless`, hoặc `ANALYZE_HEADLESS=...` |
| `ContextChangeException: Context register change conflicts` | Đặt TMode tại địa chỉ đã disassemble | Script chỉ đặt TMode khi chưa có lệnh – đừng gỡ điều kiện đó |
| Output toàn `halt_baddata` / lệnh vô nghĩa (ARM32) | Hàm ở Thumb mode nhưng được disassemble ARM | Xoá project (`rm -rf work/ghidra-project`) rồi sửa `ensureFunction` đặt TMode = 1 cho địa chỉ đó; kiểm tra trong GUI (`ghidraRun`, Ctrl+Shift+F để xem context) |
| `NO_FUNCTION` | Địa chỉ nằm giữa dữ liệu hoặc RVA sai build | Kiểm tra `script.json` và `.so` cùng build; xem `dump.cs` có `RVA: 0x0` (method abstract / không có body) |
| Muốn xem bằng GUI | | `ghidraRun`, mở `work/ghidra-project/il2cpp.gpr`; `G` → địa chỉ (`image base + RVA`) |
| Gọi lại bị chậm | Import lại mỗi lần | Script tái dùng project; chỉ import khi chưa có `il2cpp.rep` |

Analyzer đắt cần tắt nếu buộc phải auto-analyze (GUI): Decompiler Parameter ID, ARM Aggressive
Instruction Finder, Non-Returning Functions - Discovered, Stack.

## Il2CppDumper / Cpp2IL

| Triệu chứng | Xử lý |
|---|---|
| `You must install or update .NET` | `DOTNET_ROLL_FORWARD=LatestMajor` (script đã đặt) |
| `ERROR: This file may be protected.` rồi vẫn `Done!` | Vô hại (do tìm `JNI_OnLoad`) |
| `Metadata version not supported` / crash khi đọc metadata | Metadata quá mới hoặc bị sửa: Cpp2IL / Il2CppInspectorRedux; hoặc REA `inspect-il2cpp-metadata` (v24/27/29/31/39) |
| `CodeRegistration: 0` / không tìm được | `.so` bị pack/mã hoá (kiểm tra triage `protection`) hoặc sai cặp so+metadata. Thử Il2CppDumper chế độ manual hoặc dump `.so` từ bộ nhớ |
| `dump.cs` có tên nhưng địa chỉ lệch | `.so` và metadata khác build – lấy cả hai từ cùng một XAPK |

## Metadata mã hoá / ẩn

Dấu hiệu: không có magic `AF 1B B1 FA` ở đầu file, file không tồn tại, hoặc version lạ.
1. Tìm trong `assets/`, OBB, Addressables bundle (`unity_triage.py` liệt kê data).
2. Trên thiết bị được phép (root/emulator): Frida hook `il2cpp_init` hoặc `open/mmap` → dump
   vùng metadata sau khi giải mã (magic xuất hiện) → đưa file dump cho dumper.
   Công cụ: `frida-il2cpp-bridge` (hook theo tên class/method), REA `start_frida_session`.
3. Ghi rõ trong báo cáo nguồn gốc file metadata (tĩnh hay dump runtime).

## REA

| Lỗi | Xử lý |
|---|---|
| `unsupported_target: only 64-bit little-endian images` | Binary armv7: dùng Il2CppDumper (REA vẫn đọc được metadata riêng) |
| `provider_timeout` (`ghidra.startup_timeout_ms`, 330 s) khi decompile | REA để Ghidra import + analyze; với lib lớn hãy dùng `ghidra_decompile.sh` của skill. Nếu vẫn dùng REA: `REA_GHIDRA_STARTUP_TIMEOUT_MS=1800000` và tăng timeout phía client; không lặp lại cùng một lời gọi đã timeout |
| `unsupported-pointer-encoding` | Android packed relocations (APS2) – dùng Il2CppDumper |

## AssetRipper

| Triệu chứng | Xử lý |
|---|---|
| Field MonoBehaviour trống | Phải nạp cả APK/XAPK (có `global-metadata.dat` + `libil2cpp.so`) để AssetRipper dựng type tree; không nạp riêng một bundle |
| Thiếu level | Có thể ở Addressables (`assets/aa/`) – vẫn nằm trong export; hoặc tải từ server (cache trên máy: `/sdcard/Android/data/<pkg>/files`) |
| Export chậm | `--mode primary` khi chỉ cần ảnh/âm thanh; `project` khi cần ScriptableObject/prefab/scene |
| `UNCONFIRMED` | Đọc `<out>.assetripper.log`; tìm `Finished post-export` |

## Gộp XAPK thành APK đơn (chỉ khi cần cài lên máy)

```bash
cp base.apk merged.apk && zip -d merged.apk 'META-INF/*.SF' 'META-INF/*.RSA' 'META-INF/MANIFEST.MF'
(cd split && zip -qr -X ../merged.apk lib)
$BT/zipalign -f -p 4 merged.apk aligned.apk && $BT/apksigner sign --ks my.keystore --out out.apk aligned.apk
```
Chữ ký mới ⇒ gỡ bản cũ trước. Có `libpairip`/`com.pairip.application.Application` ⇒ bản ký lại
thường crash khi mở; không phải lỗi gộp. Phân tích tĩnh không bị ảnh hưởng.
