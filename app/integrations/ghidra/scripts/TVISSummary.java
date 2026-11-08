// Exports a JSON summary of the analysed program for TV Intelligence Scanner.
// Usage (headless): -postScript TVISSummary.java <output.json>
// @category TVIS
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.DefinedDataIterator;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class TVISSummary extends GhidraScript {

    private static String esc(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    private static String list(List<String> items) {
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) b.append(',');
            b.append(esc(items.get(i)));
        }
        return b.append(']').toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("output path argument required");
        }
        Program p = currentProgram;
        FunctionManager fm = p.getFunctionManager();
        List<String> functions = new ArrayList<>();
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext() && functions.size() < 300) {
            Function f = it.next();
            functions.add(f.getName() + "@" + f.getEntryPoint());
        }
        List<String> externals = new ArrayList<>();
        SymbolIterator ext = p.getSymbolTable().getExternalSymbols();
        while (ext.hasNext() && externals.size() < 500) {
            Symbol s = ext.next();
            externals.add(s.getName());
        }
        List<String> libraries = new ArrayList<>();
        for (String lib : p.getExternalManager().getExternalLibraryNames()) {
            libraries.add(lib);
        }
        int strings = 0;
        for (Object d : DefinedDataIterator.definedStrings(p)) {
            strings++;
        }
        String json = "{"
            + "\"program\":" + esc(p.getName()) + ","
            + "\"language\":" + esc(p.getLanguageID().getIdAsString()) + ","
            + "\"compiler\":" + esc(p.getCompilerSpec().getCompilerSpecID().getIdAsString()) + ","
            + "\"executable_format\":" + esc(p.getExecutableFormat()) + ","
            + "\"image_base\":" + esc(p.getImageBase().toString()) + ","
            + "\"function_count\":" + fm.getFunctionCount() + ","
            + "\"defined_strings\":" + strings + ","
            + "\"libraries\":" + list(libraries) + ","
            + "\"external_symbols\":" + list(externals) + ","
            + "\"functions_sample\":" + list(functions)
            + "}";
        try (Writer w = new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8)) {
            w.write(json);
        }
        println("TVIS summary written to " + args[0]);
    }
}
