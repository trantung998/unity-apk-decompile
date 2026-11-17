# unity-apk-decompile

Claude Code skill: dịch ngược game Unity Android (APK/XAPK/APKS/APKM) – IL2CPP và Mono.
Nội dung chính cho agent nằm trong `SKILL.md`.

## Cài đặt

Claude Code nạp skill từ `~/.claude/skills/`. Thư mục này được liên kết bằng symlink:

```bash
ln -s ~/Desktop/unity-apk-decompile ~/.claude/skills/unity-apk-decompile
```

## Cấu trúc

| Đường dẫn | Vai trò |
|---|---|
| `SKILL.md` | Quy trình, rẽ nhánh, sai lầm thường gặp |
| `scripts/unity_triage.py` | Giải nén APK/XAPK, nhận diện backend/ABI/metadata, ghi `paths.env` |
| `scripts/run_il2cppdumper.sh` | Chạy Il2CppDumper không tương tác |
| `scripts/select_targets.py` | Chọn method theo regex → `targets.tsv`, `names.tsv`, `labels.tsv` |
| `scripts/dump_class.py` | Field/offset, method/RVA của class; tra field theo offset |
| `scripts/ghidra_decompile.sh` + `scripts/ghidra/DecompileIl2cppTargets.java` | Ghidra headless `-noanalysis`, decompile có mục tiêu, tự chú thích tên |
| `scripts/assetripper_export.py` | AssetRipper headless qua HTTP API |
| `scripts/unity_yaml.py` | Đọc YAML/ScriptableObject Unity |
| `references/` | Đọc pseudocode IL2CPP, xử lý lỗi |

## Phụ thuộc

Python 3, .NET (Il2CppDumper), Ghidra (`analyzeHeadless`), AssetRipper.GUI.Free, PyYAML
(tự tạo venv `~/.cache/unity-apk-decompile/venv` nếu thiếu).
