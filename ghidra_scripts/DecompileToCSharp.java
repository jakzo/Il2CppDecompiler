
import java.util.*;
import java.util.regex.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;

import javax.swing.JTextArea;

import docking.options.OptionsService;
import generic.jar.ResourceFile;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.*;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

// ~/Downloads/ghidra_11.0_PUBLIC/support/analyzeHeadless ~/Downloads/boneworks Boneworks.gpr -process GameAssembly.dll -noanalysis -readOnly -preScript ~/Downloads/ghidra_11.0_PUBLIC/Extensions/Ghidra/Il2CppDecompiler/ghidra_scripts/DecompileToCSharp.java

public class DecompileToCSharp extends GhidraScript {
	@Override
	public void run() throws Exception {
		DecompInterface decomp = new DecompInterface();
		try {
			if (!decomp.openProgram(currentProgram)) {
				throw new Exception("Decompile error: " + decomp.getLastMessage());
			}

			DecompileOptions options = getDefaultDecompileOptions();
			// OptionsService service = state.getTool().getService(OptionsService.class);
			// if (service != null) {
			// ToolOptions opt = service.getOptions("Decompiler");
			// options.grabFromToolAndProgram(null, opt, currentProgram);
			// }
			decomp.setOptions(options);

			decomp.toggleCCode(true);
			decomp.toggleSyntaxTree(true);
			decomp.setSimplificationStyle("decompile");

			Address funcAddress = currentProgram.getAddressFactory().getAddress("18042fb81"); // PhysicsRig.OnAfterFixedUpdate
			// Function func =
			// currentProgram.getFunctionManager().getFunctionContaining(currentAddress);
			Function func = currentProgram.getFunctionManager()
					.getFunctionContaining(funcAddress);
			println("cur: " + currentAddress.toString());

			DecompileResults results = decomp.decompileFunction(func, 30, monitor);

			ClangTokenGroup tokgroup = results.getCCodeMarkup();
			HighFunction hfunc = results.getHighFunction();
			for (PcodeBlockBasic block : hfunc.getBasicBlocks()) {
				System.out.println(block.toString());
				Iterator<PcodeOp> iter = block.getIterator();
				while (iter.hasNext()) {
					PcodeOp op = iter.next();
					System.out.println(op.toString());
				}
			}

			String cCode = results.getDecompiledFunction().getC();
			writeToFile("decomp.c", cCode);

			String csCode = convertToCs(cCode);
			writeToFile("decomp.cs", csCode);

			// showTextInPanel(csCode);

			System.out.println("Decompilation complete!");
		} finally {
			decomp.dispose();
		}
	}

	private void showTextInPanel(String text) {
		println(text);
		// JPanel panel = new JPanel(new BorderLayout());
		// JTextArea textArea = new JTextArea(5, 25);
		// textArea.setEditable(false);
		// textArea.setText(text);
		// panel.add(new JScrollPane(textArea));
		// setVisible(true);
	}

	private DecompileOptions getDefaultDecompileOptions() {
		DecompileOptions opts = new DecompileOptions();

		ToolOptions toolOpts = new ToolOptions("Decompiler");
		toolOpts.setBoolean("Analysis.Simplify predication", true);
		toolOpts.setBoolean("Display.Print 'NULL' for null pointers", true);
		toolOpts.setBoolean("Display.Disable printing of type casts", true);
		opts.grabFromToolAndProgram(null, toolOpts, currentProgram);

		return opts;
	}

	private String convertToCs(String c) {
		int bodyIdx = c.indexOf("{");
		String header = c.substring(0, bodyIdx - 2);
		String body = c.substring(bodyIdx);
		String[] bodyParts = body.split("\\n\\s*\\n", 2);
		String varDeclarations = bodyParts[0];
		String code = bodyParts[1];

		// Remove MethodInfo arg
		header = header.replaceFirst(",?[\\s\\n]*MethodInfo [^)]+", "");

		// Remove `if (DAT_...` thing at the start of every method
		code = code.replaceFirst("^\\s*if \\(DAT_(?:.|\\n)+?}", "");

		// Remove null checks
		Pattern nullCheckPattern = Pattern.compile(
				"^(\\s*)if \\(\\w+ != NULL\\) \\{$");
		List<String> lines = new ArrayList(Arrays.asList(code.split("\\n")));
		for (int i = 0; i < lines.size(); i++) {
			Matcher matcher = nullCheckPattern.matcher(lines.get(i));
			if (matcher.find()) {
				lines.remove(i);
				String indentation = matcher.group(1);
				for (int j = i; j < lines.size(); j++) {
					String line = lines.get(j);
					String newLine = line.startsWith(indentation) ? line.substring(2) : line;
					lines.set(j, newLine);
					if (line.equals(indentation + "}")) {
						lines.remove(j);
						break;
					}
				}
			}
		}
		code = String.join("\n", lines);

		// null
		code = code.replaceAll("\\bNULL\\b", "null");

		// this
		code = code.replaceAll("\\b__this\\b", "this");

		// fields/vtable
		code = code.replaceAll("\\((\\w+)->(?:fields|klass->vtable)\\)", "$1");
		code = code.replaceAll("\\.(?:fields|field0_0x0)\\.", ".");

		// Remove method info arg
		code = code.replaceAll(",?[\\s\\n]*\\(MethodInfo \\*\\)0x0(?=[\\s\\n]*\\))", "");

		// Remove methodPtr
		code = code.replaceAll("\\(\\*([^;]+?)\\._\\d+_(\\w+)\\.methodPtr\\b\\)[\\s\\n]*\\([^,)]*,?[\\s\\n]*", "$1.$2(");

		// Remove casts
		code = code.replaceAll("(\\W)\\(\\w+\\W*\\)", "$1");

		// Remove getter/setter suffix
		code = code.replaceAll("_k__BackingField", "");

		// Fix generics
		code = code.replaceAll(
				"(\\w+)[\\s\\n]*<\\w+>[\\s\\n]*\\(([^)]*),[\\s\\n]*Method_\\w+[\\s\\n]*<(\\w+)>[\\s\\n]*__[\\s\\n]*\\)",
				"$1<$3>($2)");

		// Inline vars only used once
		List<String> vars = new ArrayList<String>();
		Pattern varNamePattern = Pattern.compile("\\w+(?=;)");
		for (String line : varDeclarations.split("\n")) {
			Matcher matcher = varNamePattern.matcher(line);
			if (matcher.find()) {
				vars.add(matcher.group());
			}
		}
		for (String varName : vars) {
			Pattern assignmentPattern = Pattern.compile("\\n\\s*" + varName + "\\s*=[\\s\\n]*((?:.|\\n)+?);");
			List<MatchResult> assignments = assignmentPattern.matcher(code).results().toList();
			if (assignments.size() == 1) {
				MatchResult assignment = assignments.get(0);

				Pattern usagePattern = Pattern.compile("[^.]\\b" + varName + "\\b");
				List<MatchResult> usages = usagePattern.matcher(code).results().toList();
				if (usages.size() == 2) {
					MatchResult usage = usages.get(1);
					code = code.substring(0, assignment.start()) +
							code.substring(assignment.end(), usage.start() + 1) +
							assignment.group(1) +
							code.substring(usage.end());
				}
			}
		}

		return header + " {\n" + code;
	}

	private void writeToFile(String filename, String contents) {
		try {
			String outDir = "~/Downloads/ghidra_11.0_PUBLIC/Extensions/Ghidra/Il2CppDecompiler/dist/";
			Files.write(
					Paths.get(outDir + filename),
					contents.getBytes(StandardCharsets.UTF_8));
			System.out.println("Content written to file successfully.");
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println("An error occurred while writing the file.");
		}
	}
}
