
import java.util.*;
import java.util.regex.*;

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

public class DecompileToCSharp extends GhidraScript {
	@Override
	public void run() throws Exception {
		DecompInterface decomp = new DecompInterface();
		try {
			if (!decomp.openProgram(currentProgram)) {
				Msg.error(this, "Decompile error: " + decomp.getLastMessage());
				return;
			}

			DecompileOptions options = new DecompileOptions();
			OptionsService service = state.getTool().getService(OptionsService.class);
			if (service != null) {
				ToolOptions opt = service.getOptions("Decompiler");
				options.grabFromToolAndProgram(null, opt, currentProgram);
			}
			decomp.setOptions(options);

			decomp.toggleCCode(true);
			decomp.toggleSyntaxTree(true);
			decomp.setSimplificationStyle("decompile");

			Function func = currentProgram.getFunctionManager().getFunctionContaining(currentAddress);
			DecompileResults results = decomp.decompileFunction(func, MAX_REFERENCES_TO, monitor);
			String cCode = results.getDecompiledFunction().getC();
			String csCode = convertToCs(cCode);
			showTextInPanel(csCode);
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
				"^(\\s*)if \\(\\w+ != \\(\\w+ \\*\\)0x0\\) \\{$");
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

		// this
		code = code.replaceAll("\\b__this\\b", "this");

		// fields/vtable
		code = code.replaceAll("\\((\\w+)->(?:fields|klass->vtable)\\)", "$1");
		code = code.replaceAll("\\.(?:fields|field0_0x0)\\.", ".");

		// Remove method info arg
		code = code.replaceAll(",?[\\s\\n]*\\(MethodInfo \\*\\)0x0(?=[\\s\\n]*\\))", "");

		// Remove methodPtr
		code = code.replaceAll("\\(\\*([^;]+?)\\._\\d+_(\\w+)\\.methodPtr\\b\\)\\([^,)]*\\s*", "$1.$2(");

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
}
