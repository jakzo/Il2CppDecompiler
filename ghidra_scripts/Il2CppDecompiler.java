import java.util.*;
import java.util.regex.*;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.NumberFormat;

import com.google.gson.Gson;

import ghidra.app.decompiler.*;
import ghidra.app.script.*;
import ghidra.framework.options.ToolOptions;
import ghidra.util.exception.CancelledException;

public class Il2CppDecompiler extends GhidraScript {
	private static NumberFormat usdFormatter = NumberFormat.getCurrencyInstance(Locale.US);

	ProjectData projectData = new ProjectData();

	// TODO: Decompile whole class, or even whole project
	@Override
	public void run() throws Exception {
		var transpiler = new LlmTranspiler();
		monitor.initialize(2 + transpiler.stepCount, "Setting up");

		var decomp = new DecompInterface();
		try {
			if (!decomp.openProgram(currentProgram)) {
				throw new Exception("Decompile error: " + decomp.getLastMessage());
			}

			var options = getDefaultDecompileOptions();
			decomp.setOptions(options);

			decomp.toggleCCode(true);
			decomp.toggleSyntaxTree(true);
			decomp.setSimplificationStyle("decompile");

			var funcAddress = isRunningHeadless()
					? currentProgram.getAddressFactory().getAddress(getArg(0))
					: currentAddress;
			var func = currentProgram.getFunctionManager()
					.getFunctionContaining(funcAddress);

			onProgress("Decompiling function to C");
			var results = decomp.decompileFunction(func, 30, monitor);

			// TODO: Decompile P-code directly to C# instead of C
			// var tokgroup = results.getCCodeMarkup();
			// var hfunc = results.getHighFunction();
			// for (var block : hfunc.getBasicBlocks()) {
			// println(block.toString());
			// var iter = block.getIterator();
			// while (iter.hasNext()) {
			// var op = iter.next();
			// println(op.toString());
			// }
			// }

			splitAllVars();

			var cCode = results.getDecompiledFunction().getC();
			var filePrefix = "results/" + func.getName() + "/";
			projectData.saveFile(filePrefix + "decompGhidra.c", cCode);

			var unnamedFuncMatcher = Pattern.compile("\\bFUN_[0-9a-f]+\\b").matcher(cCode);
			if (unnamedFuncMatcher.find()) {
				var funcs = unnamedFuncMatcher.group(0);
				while (unnamedFuncMatcher.find()) {
					funcs += ", " + unnamedFuncMatcher.group(0);
				}
				throw new Exception("Method contains calls to unnamed functions: " + funcs);
			}

			// var csStrCode = new HackyStringReplaceTranspiler().convertToCs(cCode);
			// projectData.saveFile(filePrefix + "decompStr.cs", csStrCode);

			var csLlmCode = transpiler.convertToCs(cCode, filePrefix);
			var finalOutputRelPath = filePrefix + "decompLlm.cs";
			projectData.saveFile(finalOutputRelPath, csLlmCode);

			println("Decompiled to: " +
					projectData.getProjectFile(finalOutputRelPath).getAbsolutePath());
		} finally {
			decomp.dispose();
		}
	}

	private String getArg(int index) {
		var args = getScriptArgs();
		return args.length > index ? args[index] : null;
	}

	private void onProgress(String message) throws CancelledException {
		monitor.increment();
		monitor.setMessage(message);
		if (isRunningHeadless()) {
			println(message);
		}
	}

	private DecompileOptions getDefaultDecompileOptions() {
		var opts = new DecompileOptions();

		var toolOpts = new ToolOptions("Decompiler");
		toolOpts.setBoolean("Analysis.Simplify predication", true);
		toolOpts.setBoolean("Display.Print 'NULL' for null pointers", true);
		toolOpts.setBoolean("Display.Disable printing of type casts", true);
		opts.grabFromToolAndProgram(null, toolOpts, currentProgram);

		return opts;
	}

	private static void splitAllVars() {
		// TODO
	}

	// TODO: Should I store data in DomainObjects so they are checked into VC?
	public class ProjectData {
		private class Config {
			String il2CppDumperOutputDir;
		}

		private final String DIR_NAME = "Il2CppDecompiler";
		private final String CONFIG_FILE_NAME = "config.json";

		private Config cachedConfig;

		public Config getConfig() throws IOException {
			if (cachedConfig != null) {
				return cachedConfig;
			}

			cachedConfig = readConfigFromFile();
			if (cachedConfig != null) {
				return cachedConfig;
			}

			cachedConfig = new Config();
			saveConfig();
			return cachedConfig;
		}

		public Config readConfigFromFile() throws IOException {
			var configFile = getProjectFile(CONFIG_FILE_NAME);
			if (!configFile.isFile()) {
				return null;
			}

			var gson = new Gson();
			try (var reader = new FileReader(configFile)) {
				return gson.fromJson(reader, Config.class);
			}
		}

		public void saveConfig() throws IOException {
			var gson = new Gson();
			var json = gson.toJson(cachedConfig);
			saveFile(CONFIG_FILE_NAME, json);
		}

		public File getProjectFile(String relPath) {
			var projectDir = getProjectRootFolder().getProjectLocator().getProjectDir();
			var dataDir = new File(projectDir, DIR_NAME);
			return new File(dataDir, relPath);
		}

		public void saveFile(String relPath, String contents) throws IOException {
			var file = getProjectFile(relPath);
			file.getParentFile().mkdirs();
			try (var writer = new FileWriter(file)) {
				writer.write(contents);
			}
		}

		public String getIl2CppDumperOutputDir(boolean promptIfUnset) throws Exception {
			var config = getConfig();
			if (config.il2CppDumperOutputDir == null && promptIfUnset) {
				var value = isRunningHeadless()
						? getArg(2) != null ? new File(getArg(2)) : null
						: askDirectory("Select Il2CppDumper output directory", "Select");
				if (value == null) {
					throw new Exception("No Il2CppDumper output directory was provided");
				}
				setIl2CppDumperOutputDir(value.getAbsolutePath());
			}
			return config.il2CppDumperOutputDir;
		}

		public void setIl2CppDumperOutputDir(String outputDir) throws IOException {
			var config = getConfig();
			config.il2CppDumperOutputDir = outputDir;
			saveConfig();
		}

		private String openAiApiKey;

		public String getOpenAiApiKey(boolean promptIfUnset) throws Exception {
			if (openAiApiKey == null && promptIfUnset) {
				var key = isRunningHeadless()
						? getArg(1)
						: askString("OpenAI API key", "Enter OpenAI API key");
				setOpenAiApiKey(key);
			}
			if (openAiApiKey == null) {
				throw new Exception("OpenAI API key is not set");
			}
			return openAiApiKey;
		}

		public void setOpenAiApiKey(String key) {
			// Don't save because it is too sensitive for plaintext config
			openAiApiKey = key;
		}
	}

	public static class Il2CppDecompilerType {
		public String namespace;
		public String category;
		public String name;
		public String fullName;
		public String cName;
		public String heading;
		public Map<String, String> items;
		public HashSet<String> properties;
		public HashSet<String> methods;
		public String rawStr;
	}

	public class Il2CppDecompilerOutput {
		private final static Pattern DUMP_CS_PATTERN = Pattern.compile(
				"(// Namespace: ([^\\n]*)\\n" +
						"[^{]*?([^\\s\\n]+) ([^\\s\\n]+)(?: : [^\\s\\n]+)?(?: //[^\\n]*\\n)?)" +
						" ?(\\{\\}|\\{.*?\\n\\})",
				Pattern.DOTALL);
		private final static Pattern FIELD_PATTERN = Pattern.compile("[^;]+?([^\\s;]+)\\s*(?:=[^;]+)?;", Pattern.DOTALL);
		private final static Pattern PROP_BACKING_FIELD_PATTERN = Pattern.compile("<(\\S+?)>k__BackingField");
		private final static Pattern PROPERTY_PATTERN = Pattern.compile("[^{}]+?([^\\s{]+)\\s*\\{[^}]*\\}", Pattern.DOTALL);
		private final static Pattern METHOD_NAME_PATTERN = Pattern.compile("[^\\s\\(\\n]+(?=\\s*\\()", Pattern.DOTALL);
		private final static String COMMENT_PATTERN = "\\s*//.*|/\\*.*?\\*/";

		public Map<String, Il2CppDecompilerType> typesByCName = new HashMap<String, Il2CppDecompilerType>();

		private Set<String> headerTokens = new HashSet<>();
		private Trie typeKeys = new Trie();
		private String outputDir;

		public Il2CppDecompilerOutput(String outputDir) throws IOException {
			this.outputDir = outputDir;
			getHeaderTokens();
			parseDumpCs();
		}

		private String readOutputFile(String filename) throws IOException {
			var file = projectData.getProjectFile("DumperOutput/" + filename);
			if (!file.exists()) {
				file.getParentFile().mkdirs();
				Files.copy(Path.of(outputDir, filename), file.toPath());
			}
			return new String(Files.readAllBytes(file.toPath()));
		}

		private void getHeaderTokens() throws IOException {
			var content = readOutputFile("il2cpp.h");
			var matcher = Pattern.compile("\\w+").matcher(content);
			while (matcher.find()) {
				headerTokens.add(matcher.group(0));
			}
		}

		private void parseDumpCs() throws IOException {
			var content = readOutputFile("dump.cs");
			var matcher = DUMP_CS_PATTERN.matcher(content);

			while (matcher.find()) {
				var type = new Il2CppDecompilerType();
				type.namespace = matcher.group(2);
				type.category = matcher.group(3);
				type.name = matcher.group(4);
				type.fullName = type.namespace.length() > 0 ? type.namespace + "." + type.name : type.name;
				type.cName = headerFixName(type.fullName);
				type.heading = matcher.group(1).replaceAll(COMMENT_PATTERN, "");
				type.items = new HashMap<>();
				type.properties = new HashSet<>();
				type.methods = new HashSet<>();
				type.rawStr = matcher.group(0);

				var sections = matcher.group(5).split("\\s*// (?=Fields|Properties|Methods\\n)");
				parseProperties(getSection(sections, "Properties"), type);
				parseFields(getSection(sections, "Fields"), type);
				parseMethods(getSection(sections, "Methods"), type);

				typesByCName.put(type.cName, type);
				typeKeys.insert(type.cName);
			}
		}

		private static String getSection(String[] sections, String name) {
			for (var section : sections) {
				if (section.startsWith(name)) {
					return section.substring(name.length() + 1);
				}
			}
			return null;
		}

		private static void parseProperties(String raw, Il2CppDecompilerType type) {
			if (raw == null)
				return;
			var matcher = PROPERTY_PATTERN.matcher(raw);

			while (matcher.find()) {
				var contents = matcher.group(0).replaceAll(COMMENT_PATTERN, "");
				var name = matcher.group(1);
				type.items.put(headerFixName(name), cleanItem(contents));
				type.properties.add(name);
			}
		}

		private static void parseFields(String raw, Il2CppDecompilerType type) {
			if (raw == null)
				return;
			var matcher = FIELD_PATTERN.matcher(raw);

			while (matcher.find()) {
				var contents = matcher.group(0).replaceAll(COMMENT_PATTERN, "");

				var name = matcher.group(1);
				var backingFieldMatcher = PROP_BACKING_FIELD_PATTERN.matcher(name);
				if (backingFieldMatcher.find() && type.properties.contains(backingFieldMatcher.group(1))) {
					// Ignore backing fields because we will include the property instead
					continue;
				}
				type.items.put(headerFixName(name), cleanItem(contents));
			}
		}

		private static Map<String, String> operatorsByName = Map.ofEntries(
				Map.entry("Implicit", "implicit"),
				Map.entry("Explicit", "explicit"),
				Map.entry("Addition", "+"),
				Map.entry("Subtraction", "-"),
				Map.entry("Multiply", "*"),
				Map.entry("Division", "/"),
				Map.entry("Modulus", "%"),
				Map.entry("Equality", "=="),
				Map.entry("Inequality", "!="),
				Map.entry("GreaterThan", ">"),
				Map.entry("LessThan", "<"),
				Map.entry("GreaterThanOrEqual", ">="),
				Map.entry("LessThanOrEqual", "<="),
				Map.entry("LeftShift", "<<"),
				Map.entry("RightShift", ">>"),
				Map.entry("Increment", "++"),
				Map.entry("Decrement", "--"),
				Map.entry("UnaryNegation", "-"));

		private static void parseMethods(String raw, Il2CppDecompilerType type) {
			if (raw == null)
				return;

			var methods = raw.split("\\}");
			for (var i = 0; i < methods.length - 1; i++) {
				var contents = (methods[i] + "}").replaceAll(COMMENT_PATTERN, "");
				var matcher = METHOD_NAME_PATTERN.matcher(contents);
				String name = null;
				while (matcher.find()) {
					name = matcher.group(0);
				}
				if (name == null) {
					continue;
				}
				type.methods.add(name);

				if (name.startsWith("get_") || name.startsWith("set_")) {
					var propertyName = name.substring(4);
					if (type.properties.contains(propertyName)) {
						continue;
					}
				}

				if (name.startsWith("op_")) {
					var operatorName = name.substring(3);
					var operator = operatorsByName.get(operatorName);
					if (operator != null) {
						contents = contents.replace(name, "operator " + operator);
					}
				}

				type.items.put(headerFixName(name), cleanItem(contents));
			}
		}

		private static final Set<String> C_KEYWORDS = new HashSet<>(Arrays.asList(
				"klass", "monitor", "register", "_cs", "auto", "friend", "template",
				"flat", "default", "_ds", "interrupt", "unsigned", "signed", "asm",
				"if", "case", "break", "continue", "do", "new", "_", "short", "union",
				"class", "namespace"));
		private static final Set<String> C_SPECIAL_KEYWORDS = new HashSet<>(Arrays.asList(
				"inline", "near", "far"));

		// Logic should match Il2CppDumper's FixName function
		// https://github.com/Perfare/Il2CppDumper/blob/master/Il2CppDumper/Outputs/StructGenerator.cs#L520
		private static String headerFixName(String name) {
			var result = name;

			if (C_KEYWORDS.contains(result)) {
				result = "_" + result;
			} else if (C_SPECIAL_KEYWORDS.contains(result)) {
				result = "_" + result + "_";
			}

			if (Pattern.matches("^[0-9]", result)) {
				return "_" + result;
			} else {
				return result.replaceAll("[^a-zA-Z0-9_]", "_");
			}
		}

		private static String cleanItem(String contents) {
			return ("\n" + contents.strip()).replaceAll("\\n\\s*", "\n  ").substring(1) + "\n";
		}
	}

	/**
	 * Originally a proof-of-concept which actually works decently well. Now it's
	 * used for simplifying the decompiled C code given to the LLM to make its job
	 * easier and reduce the chance of making mistakes.
	 */
	public class HackyStringReplaceTranspiler {
		public String convertToCs(String cCode) {
			return convertToCs(cCode, true);
		}

		public String convertToCs(String cCode, boolean includeLossyChanges) {
			int bodyIdx = cCode.indexOf("{");
			String header = cCode.substring(0, bodyIdx - 2);
			String body = cCode.substring(bodyIdx);
			String[] bodyParts = body.split("\\n\\s*\\n", 2);
			String varDeclarations = bodyParts[0];
			String code = bodyParts[1];

			if (includeLossyChanges) {
				// Remove MethodInfo arg
				header = header.replaceFirst(",?[\\s\\n]*MethodInfo [^)]+", "");
			}

			// Remove `if (DAT_...` thing at the start of every method
			code = code.replaceFirst("^\\s*if \\(DAT_(?:.|\\n)+?}", "");

			if (includeLossyChanges) {
				// Remove null checks
				Pattern nullCheckPattern = Pattern.compile(
						"^(\\s*)if \\(\\w+ != NULL\\) \\{$");
				List<String> lines = new ArrayList<>(Arrays.asList(code.split("\\n")));
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
			}
			code = code.replaceAll("\\.(?:fields|field0_0x0)\\.", ".");

			if (includeLossyChanges) {
				// Remove method info arg
				code = code.replaceAll(",?[\\s\\n]*\\(MethodInfo \\*\\)0x0(?=[\\s\\n]*\\))", "");

				// Remove methodPtr
				code = code.replaceAll("\\(\\*([^;]+?)\\._\\d+_(\\w+)\\.methodPtr\\b\\)[\\s\\n]*\\([^,)]*,?[\\s\\n]*",
						"$1.$2(");

				// Remove casts
				code = code.replaceAll("(\\W)\\(\\w+\\W*\\)", "$1");
			}

			// Remove getter/setter suffix
			code = code.replaceAll("\\b_(\\w+)_k__BackingField\\b", "$1");

			if (includeLossyChanges) {
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
			}

			return header + " {\n" + code;
		}
	}

	public class LlmTranspiler {
		public int stepCount = 3;

		public String convertToCs(String cCode, String filePrefix) throws Exception {
			onProgress("Parsing Il2CppDumper output");
			var dumperDir = projectData.getIl2CppDumperOutputDir(true);
			var il2CppDecompilerOutput = new Il2CppDecompilerOutput(dumperDir);

			// Remove things which appear all the time but GPT4 refuses to handle correctly
			var simplifiedCCode = new HackyStringReplaceTranspiler().convertToCs(cCode, false);

			var typeNameMatcher = Pattern.compile("(\\w+?)__\\w+[\\s\\n]*\\(").matcher(cCode);
			var typeCName = typeNameMatcher.find() ? typeNameMatcher.group(1) : null;
			if (typeCName == null) {
				throw new Exception("Could not find name of method's type in decompiled C code");
			}
			var type = il2CppDecompilerOutput.typesByCName.get(typeCName);
			if (type == null) {
				throw new Exception("Could not find current method's type: " + typeCName);
			}

			onProgress("LLM call 1: refactoring to C#");
			var prompt1 = generateLlmConvertToCsPrompt(simplifiedCCode, il2CppDecompilerOutput);
			projectData.saveFile(filePrefix + "llm_call_1_prompt.md", prompt1);
			var messages = new ArrayList<>(Arrays.asList(new OpenAI.Message("user", prompt1)));
			var req1 = OpenAI.Request.withDefaults(messages);

			var inputLen1 = prompt1.length();
			var approxOutputLen = (int) (inputLen1 * 0.1);
			var inputLen2 = inputLen1 + approxOutputLen;
			var approximateCost = OpenAI.estimateCost(inputLen1 + inputLen2, approxOutputLen * 2);
			var estimateCostText = "Estimated cost of querying the LLM is approximately " +
					usdFormatter.format(approximateCost) + " USD.";
			if (isRunningHeadless()) {
				println(estimateCostText);
			} else {
				askYesNo("Proceed", estimateCostText + " Do you want to proceed?");
			}

			var apiKey = projectData.getOpenAiApiKey(true);
			var openai = new OpenAI(apiKey);
			var res1 = openai.getCompletion(req1);
			var outputMessage1 = res1.choices.get(0).message;
			var output1 = outputMessage1.content;
			projectData.saveFile(filePrefix + "llm_call_1_response.md", output1);

			var prompt2Parts = new ArrayList<String>();

			var nullCheckPattern = Pattern.compile("\\b(?:null|\\?\\.)\\b");
			if (nullCheckPattern.matcher(output1).find()) {
				prompt2Parts.add(
						"There are still null checks in the code. Remove them if the decompiled code only checks them to throw an exception.");
			}

			var subPattern = Pattern.compile("\\bSUB\\d+\\(");
			if (subPattern.matcher(output1).find()) {
				prompt2Parts.add(
						"There are still SUB calls in the code. Remove them and do the equivalent logic using available C# techniques.");
			}

			var byteFieldPattern = Pattern.compile("\\._\\d+_\\d+_\\b");
			if (byteFieldPattern.matcher(output1).find()) {
				prompt2Parts.add(
						"There are still ._x_x_ fields in the code. Remove them and do the equivalent logic using available C# techniques.");
			}

			prompt2Parts.add(
					"Simplify it where possible and make sure the logic is functionally equivalent to the original decompiled output.");

			onProgress("LLM call 2: fix mistakes");
			if (prompt2Parts.size() == 0)
				return parseLlmOutput(output1, type.namespace);

			var prompt2 = "Fix the following potential issues then output just the code with no explanation:\n\n- "
					+ String.join("\n- ", prompt2Parts);
			projectData.saveFile(filePrefix + "llm_call_2_prompt.md", prompt2);
			messages.add(outputMessage1);
			messages.add(new OpenAI.Message("user", prompt2));
			var req2 = OpenAI.Request.withDefaults(messages);
			var res2 = openai.getCompletion(req2);
			var output2 = res2.choices.get(0).message.content;
			projectData.saveFile(filePrefix + "llm_call_2_response.md", output2);

			println("LLM done, total cost is " + usdFormatter.format(openai.getTotalCost()) + " USD.");

			return parseLlmOutput(output2, type.namespace);
		}

		private String parseLlmOutput(String llmResponse, String namespace) throws Exception {
			var codeBlockStartIdx = llmResponse.indexOf("```");
			if (codeBlockStartIdx == -1) {
				throw new Exception("Failed to find code block in LLM output");
			}
			var codeStartIdx = llmResponse.indexOf('\n', codeBlockStartIdx);
			if (codeStartIdx == -1) {
				throw new Exception("Failed to find code block in LLM output");
			}
			var codeEndIdx = llmResponse.lastIndexOf("\n```");
			if (codeEndIdx == -1 || codeEndIdx <= codeBlockStartIdx) {
				throw new Exception("Failed to find code block in LLM output");
			}
			var methodCode = llmResponse.substring(codeStartIdx, codeEndIdx);
			return "namespace " + namespace + " {\n" + methodCode + "\n}\n";
		}

		private String generateLlmConvertToCsPrompt(String decompiledC,
				Il2CppDecompilerOutput il2CppDecompilerOutput) {
			// TODO: Iterate over tokens in decompiled C instead of string search
			var usedTypes = il2CppDecompilerOutput.typeKeys.search(decompiledC);
			var typeContext = "";
			for (var typeCName : usedTypes) {
				var type = il2CppDecompilerOutput.typesByCName.get(typeCName);
				if (type == null)
					continue;
				typeContext += type.heading + "{\n";
				for (var itemCName : type.items.keySet()) {
					if (decompiledC.contains(itemCName)) {
						typeContext += type.items.get(itemCName);
					}
				}
				typeContext += "}\n";
			}

			return """
					This is a method of a Unity IL2CPP game decompiled using ghidra and I want you to rewrite it in C#. Note that:

					- You must remove all conditions which lead to a ThrowFooException call. Eg. when you see `if (x != NULL) { y = x.y; return; } ThrowNullReferenceException();` delete both the condition and call so that it does not check for null and the above code becomes simply `y = x.y` which will implicitly throw an exception if x is null.
					- `(someVar->fields).someProp` should be translated to `someVar.someProp`.
					- The last argument of most functions is the method info, which should be removed in the translation.
					- Fields looking like `x._0_8_` are added by Ghidra and this example means "bytes 0 up to 8 of x". They do not exist at runtime and must not be used in the output.
					- Functions like `SUB84(x, 2)` are added by Ghidra and this example means "8 byte value x truncated to 4 bytes at an offset of 2 bytes". They do not exist at runtime and must not be used in the output.
					- Try and simplify it to make it more terse and readable (eg. don't set variables if they are only used once).
					- Add a doc comment to the output method.
					- Document complex parts of the code with comments.
					- Only output code for the method given (no class surrounding it, no other methods or properties).
					- Your response should only contain C# code in a markdown code block with no explanation.

					Here is the Ghidra decompiled code:

					```c
					"""
					+ decompiledC +
					"""
							```

							Here are some C# types from the original program for reference:

							```csharp
							"""
					+ typeContext +
					"""
							```
							""";
		}

		private class OpenAI {
			private final static double C_CHARS_PER_TOKEN = 3;
			private final static String API_URL = "https://api.openai.com/v1/chat/completions";
			private final static double COST_INPUT_1K_TOKENS = 0.01;
			private final static double COST_OUTPUT_1K_TOKENS = 0.03;

			private String apiKey;
			private int totalInputTokens = 0;
			private int totalOutputTokens = 0;

			public OpenAI(String apiKey) {
				this.apiKey = apiKey;
			}

			public static int estimateTokens(String text) {
				return (int) (text.length() / C_CHARS_PER_TOKEN);
			}

			public static double estimateCost(int inputTextLen, int outputTextLen) {
				var inputCost = inputTextLen / C_CHARS_PER_TOKEN / 1000 * COST_INPUT_1K_TOKENS;
				var outputCost = outputTextLen / C_CHARS_PER_TOKEN / 1000 * COST_OUTPUT_1K_TOKENS;
				return inputCost + outputCost;
			}

			public Response getCompletion(Request req) throws Exception {
				var res = getRawCompletion(req);

				if (res.choices.size() == 0) {
					throw new Exception("No response received from LLM");
				}

				var finishReason = res.choices.get(0).finish_reason;
				if (!finishReason.equals("stop")) {
					throw new Exception("Unexpected finish reason: " + finishReason);
				}

				return res;
			}

			public Response getRawCompletion(Request req) throws Exception {
				Response res;
				if (isMockEnabled()) {
					res = Mocks.getCompletion(req);
				} else {
					var gson = new Gson();
					var client = HttpClient.newHttpClient();
					var request = HttpRequest.newBuilder()
							.uri(URI.create(API_URL))
							.header("Content-Type", "application/json")
							.header("Authorization", "Bearer " + apiKey)
							.POST(BodyPublishers.ofString(gson.toJson(req)))
							.build();

					var response = client.send(request, BodyHandlers.ofString());
					if (response.statusCode() < 200 || response.statusCode() >= 300) {
						printerr("LLM response body: " + response.body());
						throw new Exception("LLM request failed with status code: " + response.statusCode());
					}
					res = gson.fromJson(response.body(), Response.class);
				}

				totalInputTokens += res.usage.prompt_tokens;
				totalOutputTokens += res.usage.completion_tokens;

				println("LLM input tokens: " + res.usage.prompt_tokens +
						", output tokens: " + res.usage.completion_tokens);

				return res;
			}

			public double getTotalCost() {
				var inputCost = totalInputTokens / 1000.0 * COST_INPUT_1K_TOKENS;
				var outputCost = totalOutputTokens / 1000.0 * COST_OUTPUT_1K_TOKENS;
				return inputCost + outputCost;
			}

			private boolean isMockEnabled() {
				return apiKey.equals("mock");
			}

			public class Mocks {
				private final static String[] MOCK_RESPONSES = {
						"""
									{
										"id": "chatcmpl-8pYELyAgXaaZYi1FL7v3zconMH5Xa",
										"object": "chat.completion",
										"created": 1707297001,
										"model": "gpt-4-0125-preview",
										"choices": [
											{
												"index": 0,
												"message": {
													"role": "assistant",
													"content": "```csharp\n/// <summary>\n/// Called after the physics engine has updated.\n/// </summary>\npublic void OnAfterFixedUpdate()\n{\n    Vector3 gravity = Physics.gravity;\n    float fixedDeltaTime = Time.fixedDeltaTime;\n    float gravityForce = 1.0f / (fixedDeltaTime * Mathf.Abs(gravity.y) * 82.0f);\n\n    if (leftHand != null && leftHand.physHand != null)\n    {\n        leftHand.physHand.ReadSensors(leftHand.joint, ref gravityForce);\n    }\n\n    if (rightHand != null && rightHand.physHand != null)\n    {\n        rightHand.physHand.ReadSensors(rightHand.joint, ref gravityForce);\n    }\n\n    if (_ballLocoEnabled)\n    {\n        Vector3 localVelocity = Vector3.zero;\n        float localAngularVelocity = 0.0f;\n        physBody.UpdateSupporteds(gravityForce, out localVelocity, out localAngularVelocity);\n\n        groundVelocity = localVelocity;\n\n        if (m_head != null)\n        {\n            Vector3 currentPosition = m_head.position;\n            Vector3 lastPositionDelta = currentPosition - _lastHeadPos;\n            Vector3 velocity = lastPositionDelta / Time.fixedDeltaTime;\n\n            headDelta = velocity - groundVelocity;\n            _avgVel = Vector3.Lerp(_avgVel, velocity, 19.0f * Time.fixedDeltaTime);\n\n            Rigidbody rbPelvis = physBody.rbPelvis;\n            if (rbPelvis != null)\n            {\n                Vector3 pelvisVelocity = rbPelvis.velocity;\n                Vector3 avgVelocityDelta = _avgVel - pelvisVelocity;\n                pelvisAccel = avgVelocityDelta / Time.fixedDeltaTime;\n\n                this.pelvisVelocity = _avgVel;\n            }\n        }\n    }\n}\n```"
												},
												"logprobs": null,
												"finish_reason": "stop"
											}
										],
										"usage": {
											"prompt_tokens": 3068,
											"completion_tokens": 370,
											"total_tokens": 3438
										},
										"system_fingerprint": "fp_f084bcfc79"
									}
								""",
						"""
								{
									"id": "chatcmpl-8pZ18isDhvBbLZnUAGS2wuopGVpmd",
									"object": "chat.completion",
									"created": 1707300026,
									"model": "gpt-4-0125-preview",
									"choices": [
										{
											"index": 0,
											"message": {
												"role": "assistant",
												"content": "```csharp\n/// <summary>\n/// Called after the physics engine has updated.\n/// </summary>\npublic void OnAfterFixedUpdate()\n{\n    Vector3 gravity = Physics.gravity;\n    float fixedDeltaTime = Time.fixedDeltaTime;\n    float gravityForce = 1.0f / (fixedDeltaTime * Mathf.Abs(gravity.y) * 82.0f);\n\n    leftHand.physHand.ReadSensors(leftHand.joint, ref gravityForce);\n    rightHand.physHand.ReadSensors(rightHand.joint, ref gravityForce);\n\n    if (_ballLocoEnabled)\n    {\n        physBody.UpdateSupporteds(gravityForce, out Vector3 localVelocity, out _);\n        groundVelocity = localVelocity;\n\n        Vector3 currentPosition = m_head.position;\n        Vector3 lastPositionDelta = currentPosition - _lastHeadPos;\n        Vector3 velocity = lastPositionDelta / Time.fixedDeltaTime;\n\n        headDelta = velocity - groundVelocity;\n        _avgVel = Vector3.Lerp(_avgVel, velocity, 19.0f * Time.fixedDeltaTime);\n\n        Vector3 pelvisVelocity = physBody.rbPelvis.velocity;\n        Vector3 avgVelocityDelta = _avgVel - pelvisVelocity;\n        pelvisAccel = avgVelocityDelta / Time.fixedDeltaTime;\n\n        this.pelvisVelocity = _avgVel;\n    }\n}\n```"
											},
											"logprobs": null,
											"finish_reason": "stop"
										}
									],
									"usage": {
										"prompt_tokens": 3507,
										"completion_tokens": 273,
										"total_tokens": 3780
									},
									"system_fingerprint": "fp_b3142a37e1"
								}
									""",
				};

				private static int mockResponseIndex = 0;

				public static Response getCompletion(Request req) {
					var gson = new Gson();
					var json = MOCK_RESPONSES[mockResponseIndex++ % MOCK_RESPONSES.length];
					return gson.fromJson(json, Response.class);
				}
			}

			public record Request(
					String model,
					List<Message> messages,
					double temperature,
					int max_tokens,
					double top_p,
					double frequency_penalty,
					double presence_penalty) {
				public static Request withDefaults(List<Message> messages) {
					return new Request(
							"gpt-4-turbo-preview",
							messages,
							0.3,
							estimateTokens(messages.get(0).content) / 2,
							1,
							0,
							0);
				}
			}

			public static class Response {
				List<Choice> choices;
				Usage usage;
			}

			public static class Choice {
				String finish_reason;
				Message message;
			}

			@SuppressWarnings("unused")
			public static class Usage {
				int completion_tokens;
				int prompt_tokens;
				int total_tokens;
			}

			@SuppressWarnings("unused")
			public static class Message {
				public String role;
				public String content;

				public Message(String role, String content) {
					this.role = role;
					this.content = content;
				}
			}
		}
	}

	/**
	 * Fast string searcher for when there are a lot of possible strings to be
	 * found in a larger string.
	 */
	public static class Trie {
		private static class Node {
			Map<Character, Node> children = new HashMap<>();
			boolean isEnd = false;
		}

		private Node root = new Node();

		public void insert(String key) {
			var node = root;
			for (var ch : key.toCharArray()) {
				node = node.children.computeIfAbsent(ch, k -> new Node());
			}
			node.isEnd = true;
		}

		/** Is greedy and non-overlapping. */
		public Set<String> search(String str) {
			var result = new HashSet<String>();
			for (int i = 0, len = str.length(); i < len;) {
				var node = root;
				var curMatch = "";
				String longestMatch = null;

				for (var j = i; j < len; j++) {
					var ch = str.charAt(j);
					node = node.children.get(ch);
					if (node == null) {
						break;
					}
					curMatch += ch;
					if (node.isEnd) {
						longestMatch = curMatch;
					}
				}

				if (longestMatch != null) {
					result.add(longestMatch);
					i += longestMatch.length();
				} else {
					i++;
				}
			}
			return result;
		}
	}
}
