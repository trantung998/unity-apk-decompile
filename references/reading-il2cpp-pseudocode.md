# Đọc pseudocode IL2CPP từ Ghidra

## Struct runtime (con trỏ 4 byte trên ARM32, 8 byte trên ARM64)

| Kiểu | Bố cục | Nhận biết |
|---|---|---|
| `Il2CppObject` | `klass*`, `monitor*` | Field đầu của object C# ở offset `0x8` (32-bit) / `0x10` (64-bit) |
| `Il2CppString` | header + `int32 length` + UTF-16 | `+0x8`/`+0x10` = length, `+0xc`/`+0x14` = ký tự |
| `Il2CppArray` | `klass`, `monitor`, `bounds`, `max_length`, data | length ở `+0xc`/`+0x18`, phần tử bắt đầu `+0x10`/`+0x20` |
| `Il2CppClass` | `image`, `gc_desc`, `name`, `namespaze`, ... `static_fields` | static fields qua con trỏ `static_fields` (offset tuỳ version: tra `il2cpp.h`) |
| `MethodInfo` | `methodPointer` đầu tiên | tham số cuối cùng của mọi method native là `const MethodInfo*` (thường `0`) |

Offset field của class: trong `dump.cs`, mỗi field có comment `// 0x50`. `*(int *)(param_1 + 0x50)`
với `param_1` = `this` ⇒ field có offset `0x50` của class đó. Với `List<T>`: `_items` +0x8/+0x10, `_size` +0xc/+0x18.

Tham số: `param_1` = `this` (method instance), các tham số C# theo sau, cuối cùng là `MethodInfo*`.
Method static không có `this`.

## Mẫu cần bỏ qua khi đọc

```c
if (*flag == '\0') { func_0x...(Method$...); *flag = 1; }   // il2cpp_codegen_initialize_runtime_metadata
if (x == 0) { func_0x...(); }                                 // NullReferenceException
if (*(int *)(klass + 0x74) == 0) { func_0x...(klass); }       // il2cpp_runtime_class_init (offset tuỳ version)
if (len <= idx) { func_0x...(); }                             // IndexOutOfRangeException
```

## Cách metadata hiện ra (script đã tự chú thích)

- **ARM32 (PIC)**: `_UNK_<pool> + 0x<pc>` → word ở literal pool + PC = địa chỉ ô GOT → dereference
  = slot metadata. Script ghi `/* Method$HashSet<PassengerEntity>.Contains() */` ngay sau biểu thức.
- **ARM64**: `PTR_DAT_<got>` → con trỏ (đã relocation trong Ghidra; giá trị trong file là 0) tới slot.
  Script ghi `PTR_DAT_0b287500/*Method$EntityQuery.GetSingleton<DrainSettings>()*/`.
- `X_TypeInfo` = class được dùng (new, is/as, static field). `Method$A.B()` = method generic/virtual
  được gọi qua MethodInfo. `StringLiteral "..."` = chuỗi C#.

## Gọi hàm

- Gọi trực tiếp tới method C# → tên đầy đủ từ `script.json` (generic được **specialize**: mỗi
  instantiation một địa chỉ; `__Il2CppFullySharedGenericType` = bản chia sẻ).
- Virtual: `(**(code **)(*(int *)obj + off))(obj, ..., *(...)(*(int *)obj + off + 4))` → vtable slot
  `{methodPtr, MethodInfo*}`; tra slot trong `dump.cs` (`// Slot: N`) của class gốc.
- Interface: đi qua helper resolve (`func_0x...`) với `Method$IFoo.Bar()` làm tham số.
- Burst/ECS (`$BurstManaged`, `__codegen__`): logic thật có thể nằm trong job `Execute` hoặc
  trong `lib_burst_generated.so` (không có metadata – khó hơn nhiều).

## Quy trình dọn một hàm

1. Đọc chữ ký C# trong `dump.cs` (tham số, kiểu trả về, field của class).
2. Đổi tên `param_n` theo chữ ký; thay `this + 0xNN` bằng tên field.
3. Xoá các khối init/null-check ở trên.
4. Callee chưa rõ: thêm vào `targets.tsv`, chạy lại (vài giây).
5. Viết lại thành C#/pseudo sạch, đánh dấu chỗ không chắc (`// suy luận`).
6. Đối chiếu hằng số với asset (ScriptableObject) – asset là nguồn quan sát, code chỉ là suy luận.

ARM32 có áp lực thanh ghi → nhiều biến tái sử dụng/inline; đừng tin tên biến Ghidra. Nếu output
rác (`halt_baddata`), hàm có thể ở Thumb mode: xem `troubleshooting.md`.
