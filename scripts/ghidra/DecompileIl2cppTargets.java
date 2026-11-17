// Targeted IL2CPP decompile for a program imported with -noanalysis.
// Args: <outDir> <targets.tsv> [names.tsv] [labels.tsv]
//   targets.tsv: rva_hex \t safe_name \t full_name   (rva = script.json Address, no image base)
//   names.tsv:   rva_hex \t method name   (names callees so pseudocode is readable)
//   labels.tsv:  rva_hex \t label         (metadata / string-literal slots)
// Writes <outDir>/<safe_name>.c and <outDir>/_index.tsv. Never analyzes the whole binary.
//@category IL2CPP
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

public class DecompileIl2cppTargets extends GhidraScript {
  Map<Long, String> names = new HashMap<>(), labels = new HashMap<>();
  long base;
  TreeSet<Long> starts;

  Map<Long, String> load(String path) throws IOException {
    Map<Long, String> m = new HashMap<>();
    if (path == null || !Files.exists(Paths.get(path))) return m;
    try (BufferedReader r = Files.newBufferedReader(Paths.get(path))) {
      for (String l; (l = r.readLine()) != null; ) {
        int t = l.indexOf('\t');
        if (t > 0) m.put(Long.parseLong(l.substring(0, t), 16), l.substring(t + 1));
      }
    }
    return m;
  }

  String lookup(long ghidraAddr) {
    long r = ghidraAddr - base;
    String n = labels.get(r);
    return n != null ? n : names.get(r);
  }

  boolean unnamed(Address a) {
    Symbol s = getSymbolAt(a);
    return s == null || s.isDynamic() || s.getSource() == SourceType.DEFAULT;
  }

  String sym(String s) { return s.replaceAll("[^A-Za-z0-9_.$<>,]", "_"); }

  Function ensureFunction(Address a, String name) throws Exception {
    Register tmode = currentProgram.getRegister("TMode");
    // script.json carries no Thumb bit; only seed ARM mode where nothing is disassembled yet.
    if (tmode != null && getInstructionAt(a) == null) {
      try { currentProgram.getProgramContext().setValue(tmode, a, a, BigInteger.ZERO); }
      catch (Exception ignored) { }
    }
    if (getInstructionAt(a) == null) disassemble(a);
    Function f = getFunctionAt(a);
    if (f == null) f = createFunction(a, name == null ? null : sym(name));
    if (f != null && name != null && f.getName().startsWith("FUN_"))
      f.setName(sym(name), SourceType.USER_DEFINED);
    return f;
  }

  // Without analysis, il2cpp throw helpers are not known noreturn. On ARM32 the code after
  // `bl throw` is the literal pool, which then gets disassembled as code and the function
  // runs into the next method. Rule: a call whose fall-through is a word this function loads
  // (literal pool) targets a noreturn helper. Mark it, turn pool words into data, re-create.
  Function fixBoundaries(Function f, Address a, String name) throws Exception {
    Long next = starts == null ? null : starts.higher(a.getOffset() - base);
    if (next == null) return f;
    Address end = toAddr(base + next - 1);
    Set<Address> pool = new HashSet<>();
    for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
      if (ins.getAddress().compareTo(end) > 0) continue;
      if (!ins.getMnemonicString().toLowerCase().startsWith("ldr")) continue;
      for (int op = 0; op < ins.getNumOperands(); op++) {  // no refs without analysis: read operands
        if (!ins.getDefaultOperandRepresentation(op).startsWith("[0x")) continue;  // ldr rX,[0xADDR]
        for (Object o : ins.getOpObjects(op)) {
          Address t = o instanceof Address ? (Address) o
              : o instanceof ghidra.program.model.scalar.Scalar ? toAddr(((ghidra.program.model.scalar.Scalar) o).getUnsignedValue()) : null;
          if (t != null && t.compareTo(a) > 0 && t.compareTo(end) <= 0) pool.add(t);
        }
      }
    }
    boolean changed = false;
    for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
      Address ft = ins.getFallThrough();
      if (!ins.getFlowType().isCall() || ft == null || !pool.contains(ft)) continue;
      for (Address t : ins.getFlows()) {
        Function h = getFunctionAt(t);
        if (h == null) { if (getInstructionAt(t) == null) disassemble(t); h = createFunction(t, null); }
        if (h != null && !h.hasNoReturn()) {
          h.setNoReturn(true);
          if (h.getSymbol().getSource() == SourceType.DEFAULT || h.getName().startsWith("thunk_FUN_"))
            h.setName("il2cpp_throw_noreturn_" + t, SourceType.USER_DEFINED);
          println("NORETURN " + h.getName() + " @" + t);
        }
        changed = true;
      }
    }
    if (!changed) return f;
    removeFunction(f);
    for (Address p : pool) {
      Instruction pi = getInstructionContaining(p);
      if (pi != null) clearListing(pi.getAddress(), pi.getMaxAddress());
      try { createDWord(p); } catch (Exception ignored) { }
    }
    if (getInstructionAt(a) == null) disassemble(a);
    Function g = createFunction(a, sym(name));
    return g != null ? g : f;
  }

  public void run() throws Exception {
    String[] a = getScriptArgs();
    File out = new File(a[0]); out.mkdirs();
    if (a.length > 2) names = load(a[2]);
    starts = new TreeSet<>(names.keySet());
    if (a.length > 3) labels = load(a[3]);
    base = currentProgram.getImageBase().getOffset();
    println("IMAGE_BASE=0x" + Long.toHexString(base) + " LANGUAGE=" + currentProgram.getLanguageID()
        + " names=" + names.size() + " labels=" + labels.size());
    DecompInterface di = new DecompInterface();
    di.openProgram(currentProgram);
    Pattern pic = Pattern.compile("_?(?:UNK|DAT|PTR_DAT)_([0-9a-fA-F]{6,16})\\s*\\+\\s*0x([0-9a-fA-F]+)");
    Pattern dat = Pattern.compile("\\b(?:PTR_)?DAT_([0-9a-fA-F]{6,16})\\b(?!\\s*\\+\\s*0x)");
    Pattern callee =Pattern.compile("func_0x([0-9a-fA-F]+)");
    try (PrintWriter idx = new PrintWriter(new File(out, "_index.tsv"))) {
      for (String line : Files.readAllLines(Paths.get(a[1]))) {
        if (line.isBlank() || line.startsWith("#")) continue;
        String[] p = line.split("\t");
        long rva = Long.parseLong(p[0].replace("0x", ""), 16) & ~1L;
        String safe = p[1], full = p.length > 2 ? p[2] : p[1];
        Address at = toAddr(base + rva);
        if (monitor.isCancelled()) break;
        Function f = ensureFunction(at, full);
        if (f == null) { println("NO_FUNCTION " + safe + " @" + at); idx.println(safe + "\t" + at + "\tNO_FUNCTION"); continue; }
        if (currentProgram.getRegister("TMode") != null) f = fixBoundaries(f, at, full);
        // Name callees and label referenced metadata so the decompiler prints names.
        int namedCallees = 0, namedData = 0;
        for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
          for (Reference r : ins.getReferencesFrom()) {
            long dr = r.getToAddress().getOffset() - base;
            if (r.getReferenceType().isCall()) {
              String n = names.get(dr);
              if (n != null && ensureFunction(r.getToAddress(), n) != null) namedCallees++;
            } else if (unnamed(r.getToAddress())) {
              String n = labels.get(dr), prefix = "";
              if (n == null) {  // arm64/x64: GOT entry pointing at the metadata slot
                try {
                  long ptr = currentProgram.getDefaultPointerSize() == 8
                      ? getLong(r.getToAddress()) : getInt(r.getToAddress()) & 0xffffffffL;
                  n = lookup(ptr); prefix = "PTR_";
                } catch (Exception ignored) { }
              }
              if (n != null) { createLabel(r.getToAddress(), prefix + sym(n), true); namedData++; }
            }
          }
        }
        DecompileResults dr = di.decompileFunction(f, 120, monitor);
        String c = dr.decompileCompleted() ? dr.getDecompiledFunction().getC() : "// DECOMPILE FAILED: " + dr.getErrorMessage();
        // ARM32 PIC: `_UNK_<pool> + <pc>` = slot address. Resolve the pool word and annotate.
        StringBuffer sb = new StringBuffer();
        Matcher m = pic.matcher(c);
        while (m.find()) {
          String rep = m.group(0);
          try {
            long pool = Long.parseLong(m.group(1), 16), pc = Long.parseLong(m.group(2), 16);
            long slot = (getInt(toAddr(pool)) & 0xffffffffL) + pc;
            String n = lookup(slot);
            if (n == null) {  // usually a GOT entry: dereference once (relocated or raw)
              try {
                long ptr = getInt(toAddr(slot)) & 0xffffffffL;
                n = lookup(ptr);
                if (n == null) n = lookup(ptr + base);
              } catch (Exception ignored) { }
            }
            if (n != null) rep = rep + " /* " + n.replace("*/", "*_/") + " */";
          } catch (Exception ignored) { }
          m.appendReplacement(sb, Matcher.quoteReplacement(rep));
        }
        m.appendTail(sb);
        // arm64/x64: adrp+ldr shows as PTR_DAT_<got> or DAT_<slot>; resolve slot or pointer target.
        m = dat.matcher(sb.toString()); sb = new StringBuffer();
        while (m.find()) {
          String n = null;
          try {
            Address g = toAddr(Long.parseLong(m.group(1), 16));
            n = lookup(g.getOffset());
            if (n == null) {
              long ptr = currentProgram.getDefaultPointerSize() == 8 ? getLong(g) : getInt(g) & 0xffffffffL;
              n = lookup(ptr);
            }
          } catch (Exception ignored) { }
          m.appendReplacement(sb, Matcher.quoteReplacement(n == null ? m.group(0) : m.group(0) + "/*" + n.replace("*/", "*_/") + "*/"));
        }
        m.appendTail(sb);
        m = callee.matcher(sb.toString()); sb = new StringBuffer();
        while (m.find()) {
          String n = names.get(Long.parseLong(m.group(1), 16) - base);
          m.appendReplacement(sb, Matcher.quoteReplacement(n == null ? m.group(0) : m.group(0) + "/*" + n + "*/"));
        }
        m.appendTail(sb);
        try (PrintWriter w = new PrintWriter(new File(out, safe + ".c"))) {
          w.println("// " + full);
          w.println("// rva=0x" + Long.toHexString(rva) + " address=" + at + " image_base=0x" + Long.toHexString(base));
          w.println("// Ghidra pseudocode of IL2CPP native code: inferred, not original C#.");
          w.print(sb);
        }
        println("DONE " + safe + " ok=" + dr.decompileCompleted() + " callees=" + namedCallees + " data=" + namedData);
        idx.println(safe + "\t" + at + "\t" + (dr.decompileCompleted() ? "OK" : "FAIL"));
      }
    }
    di.dispose();
  }
}
